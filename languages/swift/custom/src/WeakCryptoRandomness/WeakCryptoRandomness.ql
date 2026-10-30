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
import codeql.swift.StringFormat

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
 * Holds if `lit` is a string literal whose first format placeholder is the
 * SQLCipher key value.
 */
private predicate isPragmaKeyFormatLiteral(StringLiteralExpr lit) {
  lit.getValue().regexpMatch("(?is)\\s*PRAGMA\\s+(\\w+\\.)?(re)?key\\s*=\\s*'?%@.*")
}

/**
 * The expression immediately following a SQLCipher `PRAGMA key` or `rekey`
 * prefix in a SQL statement passed to a SQL execution API.
 */
class SqlCipherPragmaKeySink extends DataFlow::Node {
  SqlCipherPragmaKeySink() {
    exists(StringLiteralExpr lit, AddExpr addition, SqlInjectionSink sqlSink |
      isPragmaKeyLiteral(lit) and
      (
        addition.getLeftOperand() = lit
        or
        exists(DeclRefExpr prefix |
          addition.getLeftOperand() = prefix and
          TaintTracking::localTaint(DataFlow::exprNode(lit), DataFlow::exprNode(prefix))
        )
      ) and
      TaintTracking::localTaint(DataFlow::exprNode(addition), sqlSink) and
      this.asExpr() = addition.getRightOperand()
    )
    or
    exists(
      InterpolatedStringLiteralExpr interpolated, TapExpr tap, StringLiteralExpr lit,
      ApplyExpr appendLiteral, ApplyExpr appendInterpolation, int prefixIndex,
      int valueIndex, SqlInjectionSink sqlSink
    |
      tap = interpolated.getAppendingExpr() and
      tap.getBody().getElement(prefixIndex) = appendLiteral and
      tap.getBody().getElement(valueIndex) = appendInterpolation and
      prefixIndex < valueIndex and
      appendLiteral.getStaticTarget().getName() = "appendLiteral(_:)" and
      appendLiteral.getAnArgument().getExpr() = lit and
      isPragmaKeyLiteral(lit) and
      appendInterpolation.getStaticTarget().getName() = "appendInterpolation(_:)" and
      not exists(int previousIndex, ApplyExpr previous |
        tap.getBody().getElement(previousIndex) = previous and
        previous.getStaticTarget().getName() = "appendInterpolation(_:)" and
        prefixIndex < previousIndex and
        previousIndex < valueIndex
      ) and
      TaintTracking::localTaint(DataFlow::exprNode(interpolated), sqlSink) and
      this.asExpr() = appendInterpolation.getAnArgument().getExpr()
    )
    or
    exists(
      StringInitWithFormat formatInit, FormattingFunctionCall formatCall,
      StringLiteralExpr format, SqlInjectionSink sqlSink
    |
      formatCall.getStaticTarget() = formatInit and
      formatCall.getFormat() = format and
      isPragmaKeyFormatLiteral(format) and
      TaintTracking::localTaint(DataFlow::exprNode(formatCall), sqlSink) and
      this.asExpr() = formatCall.getArgument(1).getExpr()
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
