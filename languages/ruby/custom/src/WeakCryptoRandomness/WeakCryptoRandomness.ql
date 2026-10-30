/**
 * @name Static initialization vector for encryption
 * @description Encrypting with a hard-coded initialization vector (IV) makes the
 *              ciphertext deterministic, so identical plaintexts produce identical
 *              ciphertexts and the IV no longer provides the randomness the cipher
 *              mode requires.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id rb/weak-crypto-randomness
 * @tags security
 *       external/cwe/cwe-329
 *       external/cwe/cwe-1204
 */

import codeql.ruby.AST
import codeql.ruby.ApiGraphs
import codeql.ruby.CFG
import codeql.ruby.DataFlow
import codeql.ruby.TaintTracking

/** Gets an API node for `OpenSSL::Cipher` or one of its algorithm-specific classes. */
API::Node cipherClass() {
  result = API::getTopLevelMember("OpenSSL").getMember("Cipher")
  or
  result = cipherClass().getAMember()
}

/**
 * A call to `OpenSSL::Cipher.new` (or similar). OpenSSL defaults to decryption
 * mode, so encryption requires an explicit `encrypt` call.
 */
class CipherInstantiation extends DataFlow::CallNode {
  CipherInstantiation() { this = cipherClass().getAnInstantiation() }
}

private DataFlow::Node cipherReceiverNode(MethodCall call) {
  result.asExpr().getExpr() = call.getReceiver()
}

module CipherInstanceConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof CipherInstantiation }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      call.getMethodName() in ["iv=", "encrypt", "decrypt", "random_iv"] and
      sink = cipherReceiverNode(call)
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module CipherInstanceFlow = DataFlow::Global<CipherInstanceConfig>;

private predicate cipherCall(CipherInstantiation cipher, MethodCall call, string name) {
  call.getMethodName() = name and
  CipherInstanceFlow::flow(cipher, cipherReceiverNode(call))
}

private predicate canReachWithoutDecrypt(
  CipherInstantiation cipher, CfgNode startNode, CfgNode endNode
) {
  startNode = endNode
  or
  exists(CfgNode next |
    next = startNode.getASuccessor() and
    not exists(MethodCall decryptCall |
      cipherCall(cipher, decryptCall, "decrypt") and
      decryptCall.getControlFlowNode() = next
    ) and
    canReachWithoutDecrypt(cipher, next, endNode)
  )
}

private predicate hasEncryptingModeAtIv(CipherInstantiation cipher, MethodCall ivCall) {
  cipherCall(cipher, ivCall, "iv=") and
  exists(MethodCall encryptCall |
    cipherCall(cipher, encryptCall, "encrypt") and
    canReachWithoutDecrypt(cipher, encryptCall.getControlFlowNode(), ivCall.getControlFlowNode())
  )
}

/** A string literal with a constant value, used as a hard-coded IV candidate. */
class StaticIvSource extends DataFlow::Node {
  StaticIvSource() {
    exists(StringLiteral lit |
      this.asExpr().getExpr() = lit and
      exists(lit.getConstantValue())
    )
  }
}

/** The value assigned to the `iv` of an encrypting cipher, as in `cipher.iv = value`. */
class CipherIvSink extends DataFlow::Node {
  CipherIvSink() {
    exists(CipherInstantiation cipher, MethodCall ivCall |
      hasEncryptingModeAtIv(cipher, ivCall) and
      this.asExpr().getExpr() = ivCall.getArgument(0)
    )
  }
}

private predicate isFreshRandomCall(MethodCall call) {
  exists(DataFlow::CallNode apiCall |
    apiCall = API::getTopLevelMember("SecureRandom").getAMethodCall(_) and
    call = apiCall.asExpr().getExpr()
  )
  or
  exists(DataFlow::CallNode apiCall |
    apiCall = API::getTopLevelMember("OpenSSL").getMember("Random").getAMethodCall("random_bytes") and
    call = apiCall.asExpr().getExpr()
  )
  or
  cipherCall(_, call, "random_iv")
}

module StaticIvConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof StaticIvSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof CipherIvSink }

  predicate isBarrier(DataFlow::Node node) {
    exists(MethodCall concatenation, MethodCall randomCall |
      node.asExpr().getExpr() = concatenation and
      concatenation.getMethodName() = "+" and
      isFreshRandomCall(randomCall) and
      randomCall.getParent+() = concatenation
    )
    or
    exists(StringLiteral interpolation, MethodCall randomCall |
      node.asExpr().getExpr() = interpolation and
      isFreshRandomCall(randomCall) and
      randomCall.getParent+() = interpolation
    )
  }

  /**
   * Holds if `pred` is the value assigned to a constant and `succ` is a read of
   * that constant, as in `IV = "..."` followed by a use of `IV` (possibly in
   * another file). Global data flow does not otherwise track constants.
   */
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(ConstantAssignment write, ConstantReadAccess read |
      write.getAQualifiedName() = read.getAQualifiedName() and
      pred.asExpr().getExpr() = write.getParent().(AssignExpr).getRightOperand() and
      succ.asExpr().getExpr() = read
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module StaticIvFlow = TaintTracking::Global<StaticIvConfig>;

import StaticIvFlow::PathGraph

from StaticIvFlow::PathNode source, StaticIvFlow::PathNode sink
where StaticIvFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "A $@ is used as the initialization vector for this encryption.", source.getNode(),
  "hard-coded value"
