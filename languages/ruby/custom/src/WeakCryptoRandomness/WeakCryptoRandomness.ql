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
import codeql.ruby.DataFlow
import codeql.ruby.TaintTracking

/** Gets an API node for `OpenSSL::Cipher` or one of its algorithm-specific classes. */
API::Node cipherClass() {
  result = API::getTopLevelMember("OpenSSL").getMember("Cipher")
  or
  result = cipherClass().getAMember()
}

/**
 * A call to `OpenSSL::Cipher.new` (or similar) whose instance is not put into
 * decryption mode. OpenSSL ciphers encrypt by default.
 */
class EncryptingCipherInstantiation extends DataFlow::CallNode {
  EncryptingCipherInstantiation() {
    this = cipherClass().getAnInstantiation() and
    not exists(this.getAMethodCall("decrypt"))
  }
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
    exists(EncryptingCipherInstantiation cipher |
      this = cipher.getAMethodCall("iv=").getArgument(0)
    )
  }
}

module StaticIvConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof StaticIvSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof CipherIvSink }

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
