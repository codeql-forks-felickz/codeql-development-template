/**
 * @name JWT payload decoded without signature verification
 * @description Manually base64-decoding the payload segment of a JSON Web Token and
 *              trusting its claims without verifying the token signature allows an
 *              attacker to forge claims such as roles or user identifiers.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id cs/unverified-jwt-payload-decode
 * @tags security
 *       external/cwe/cwe-345
 *       external/cwe/cwe-347
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking
import UnverifiedJwtPayloadDecodeFlow::PathGraph

/** A call to `string.Split` whose separator is the JWT segment separator `.`. */
class JwtSplitCall extends MethodCall {
  JwtSplitCall() {
    this.getTarget().hasFullyQualifiedName("System", "String", "Split") and
    exists(Expr sep | sep = this.getArgument(0) |
      sep.(CharLiteral).getValue() = "."
      or
      sep.(StringLiteral).getValue() = "."
    )
  }

  /** Holds if segment `index` of the split result is read. */
  predicate readsSegment(ArrayAccess aa, int index) {
    DataFlow::localExprFlow(this, aa.getQualifier()) and
    aa.getIndex(0).getValue().toInt() = index
  }

  /** Holds if segment `2` flows into a comparison, equality, or verification call. */
  predicate verifiesSignature() {
    exists(ArrayAccess signature, ComparisonOperation comparison |
      this.readsSegment(signature, 2) and
      (
        DataFlow::localExprFlow(signature, comparison.getLeftOperand())
        or
        DataFlow::localExprFlow(signature, comparison.getRightOperand())
      )
    )
    or
    exists(ArrayAccess signature, Base64DecodeCall decoder, ComparisonOperation comparison |
      this.readsSegment(signature, 2) and
      DataFlow::localExprFlow(signature, decoder.getArgument(0)) and
      (
        DataFlow::localExprFlow(decoder, comparison.getLeftOperand())
        or
        DataFlow::localExprFlow(decoder, comparison.getRightOperand())
      )
    )
    or
    exists(ArrayAccess signature, MethodCall verification, int argument |
      this.readsSegment(signature, 2) and
      DataFlow::localExprFlow(signature, verification.getArgument(argument)) and
      verification.getTarget().getName().regexpMatch("(?i).*(verify|equals).*")
    )
    or
    exists(ArrayAccess signature, Base64DecodeCall decoder, MethodCall verification, int argument |
      this.readsSegment(signature, 2) and
      DataFlow::localExprFlow(signature, decoder.getArgument(0)) and
      DataFlow::localExprFlow(decoder, verification.getArgument(argument)) and
      verification.getTarget().getName().regexpMatch("(?i).*(verify|equals).*")
    )
  }
}

/**
 * An access to the payload segment (index 1) of a JWT split on `.`, where the
 * signature segment (index 2) is not used in a verification-like operation.
 */
class JwtPayloadSegment extends ArrayAccess {
  JwtPayloadSegment() {
    exists(JwtSplitCall split |
      split.readsSegment(this, 1) and
      not split.verifiesSignature()
    )
  }

  JwtSplitCall getSplitCall() { result.readsSegment(this, 1) }
}

/** A call to a base64 decoding method. */
class Base64DecodeCall extends MethodCall {
  Base64DecodeCall() {
    this.getTarget()
        .hasFullyQualifiedName("System", "Convert", ["FromBase64String", "TryFromBase64String"])
    or
    this.getTarget()
        .hasFullyQualifiedName("Microsoft.IdentityModel.Tokens", "Base64UrlEncoder",
          ["Decode", "DecodeBytes"])
    or
    this.getTarget()
        .hasFullyQualifiedName("Microsoft.AspNetCore.WebUtilities", "WebEncoders", "Base64UrlDecode")
  }
}

/** An argument to a base64 decoding method. */
class Base64DecodeSink extends Expr {
  Base64DecodeSink() { exists(Base64DecodeCall decoder | this = decoder.getArgument(0)) }
}

predicate hasSignatureValidationEnabled(Expr parameters) {
  exists(
    ObjectCreation creation, ObjectInitializer initializer, MemberInitializer enabled,
    MemberInitializer key
  |
    DataFlow::localExprFlow(creation, parameters) and
    initializer = creation.getInitializer() and
    enabled = initializer.getAMemberInitializer() and
    enabled.getLeftOperand().(PropertyAccess).getTarget().hasName("ValidateIssuerSigningKey") and
    enabled.getRightOperand().(BoolLiteral).getValue() = "true" and
    key = initializer.getAMemberInitializer() and
    key.getLeftOperand().(PropertyAccess).getTarget().hasName("IssuerSigningKey")
  )
}

predicate validatedBeforeDecode(JwtPayloadSegment payload, Base64DecodeCall decoder) {
  exists(JwtSplitCall split, MethodCall validation |
    split = payload.getSplitCall() and
    validation
        .getTarget()
        .hasFullyQualifiedName("System.IdentityModel.Tokens.Jwt", "JwtSecurityTokenHandler",
          "ValidateToken") and
    DataFlow::localExprFlow(validation.getArgument(0), split.getQualifier()) and
    hasSignatureValidationEnabled(validation.getArgument(1)) and
    validation
        .getControlFlowNode()
        .getBasicBlock()
        .dominates(decoder.getControlFlowNode().getBasicBlock())
  )
  or
  exists(
    JwtSplitCall split, MethodCall validation, AwaitExpr awaited, IfStmt guard,
    LogicalNotExpr invalidResult, PropertyAccess isValid, ThrowStmt failure
  |
    split = payload.getSplitCall() and
    validation
        .getTarget()
        .hasFullyQualifiedName("Microsoft.IdentityModel.JsonWebTokens", "JsonWebTokenHandler",
          "ValidateTokenAsync") and
    DataFlow::localExprFlow(validation.getArgument(0), split.getQualifier()) and
    hasSignatureValidationEnabled(validation.getArgument(1)) and
    awaited.getChild(0) = validation and
    DataFlow::localExprFlow(awaited, isValid.getQualifier()) and
    isValid.getTarget().hasName("IsValid") and
    invalidResult = guard.getCondition() and
    invalidResult.getOperand() = isValid and
    failure.getParent*() = guard.getThen() and
    guard
        .getControlFlowNode()
        .getBasicBlock()
        .dominates(decoder.getControlFlowNode().getBasicBlock())
  )
}

module UnverifiedJwtPayloadDecodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof JwtPayloadSegment }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof Base64DecodeSink }
}

module UnverifiedJwtPayloadDecodeFlow = TaintTracking::Global<UnverifiedJwtPayloadDecodeConfig>;

from UnverifiedJwtPayloadDecodeFlow::PathNode source, UnverifiedJwtPayloadDecodeFlow::PathNode sink
where
  UnverifiedJwtPayloadDecodeFlow::flowPath(source, sink) and
  not validatedBeforeDecode(source.getNode().asExpr().(JwtPayloadSegment),
    sink.getNode().asExpr().getParent().(Base64DecodeCall))
select sink.getNode(), source, sink,
  "JWT payload segment from $@ is base64-decoded without verifying the token signature; its claims can be forged.",
  source.getNode(), "this token"
