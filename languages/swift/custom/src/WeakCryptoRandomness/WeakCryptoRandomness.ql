/**
 * @name Encryption key derived from a device identifier
 * @description Using a device identifier such as `identifierForVendor` or
 *              `advertisingIdentifier` as encryption key material produces a
 *              predictable, non-random key that is readable by other code
 *              running on the device.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id swift/weak-crypto-randomness
 * @tags security
 *       external/cwe/cwe-330
 *       external/cwe/cwe-321
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.security.HardcodedEncryptionKeyExtensions
import codeql.swift.security.SqlInjectionExtensions

/**
 * A read of a device identifier, which is an identifier rather than random
 * secret key material.
 */
class DeviceIdentifierSource extends MemberRefExpr {
  DeviceIdentifierSource() {
    this.getMember().(FieldDecl).hasQualifiedName("UIDevice", "identifierForVendor")
    or
    this.getMember().(FieldDecl).hasQualifiedName("ASIdentifierManager", "advertisingIdentifier")
  }
}

/**
 * Holds if `lit` is a string literal that starts a SQLCipher `PRAGMA key` or
 * `PRAGMA rekey` statement.
 */
private predicate isPragmaKeyLiteral(StringLiteralExpr lit) {
  lit.getValue().regexpMatch("(?is)\\s*PRAGMA\\s+(\\w+\\.)?(re)?key\\s*=.*")
}

/**
 * A SQL statement passed to a SQL execution API that sets a SQLCipher
 * encryption key (`PRAGMA key = '...'` or `PRAGMA rekey = '...'`).
 */
class SqlCipherPragmaKeySink extends DataFlow::Node instanceof SqlInjectionSink {
  SqlCipherPragmaKeySink() {
    exists(StringLiteralExpr lit |
      isPragmaKeyLiteral(lit) and
      TaintTracking::localTaint(DataFlow::exprNode(lit), this)
    )
  }
}

module WeakCryptoRandomnessConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node.asExpr() instanceof DeviceIdentifierSource }

  predicate isSink(DataFlow::Node node) {
    node instanceof HardcodedEncryptionKeySink or
    node instanceof SqlCipherPragmaKeySink
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    // `UUID.uuidString` and similar string representations of an identifier.
    exists(MemberRefExpr mre |
      mre.getMember()
          .(FieldDecl)
          .hasQualifiedName(["UUID", "NSUUID"], ["uuidString", "description"]) and
      nodeFrom.asExpr() = mre.getBase() and
      nodeTo.asExpr() = mre
    )
  }
}

module WeakCryptoRandomnessFlow = TaintTracking::Global<WeakCryptoRandomnessConfig>;

import WeakCryptoRandomnessFlow::PathGraph

from WeakCryptoRandomnessFlow::PathNode source, WeakCryptoRandomnessFlow::PathNode sink
where WeakCryptoRandomnessFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This encryption key is derived from $@, which is a device identifier rather than cryptographically random key material.",
  source.getNode(), source.getNode().toString()
