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
}

/**
 * An access to the payload segment (index 1) of a JWT split on `.`, where the
 * signature segment (index 2) of the same split result is never read.
 */
class JwtPayloadSegment extends ArrayAccess {
  JwtPayloadSegment() {
    exists(JwtSplitCall split |
      split.readsSegment(this, 1) and
      not split.readsSegment(_, 2)
    )
  }
}

/** An argument to a base64 decoding method. */
class Base64DecodeSink extends Expr {
  Base64DecodeSink() {
    exists(MethodCall mc, Method target |
      target = mc.getTarget() and
      this = mc.getArgument(0)
    |
      target.hasFullyQualifiedName("System", "Convert", ["FromBase64String", "TryFromBase64String"])
      or
      target
          .hasFullyQualifiedName("Microsoft.IdentityModel.Tokens", "Base64UrlEncoder",
            ["Decode", "DecodeBytes"])
      or
      target
          .hasFullyQualifiedName("Microsoft.AspNetCore.WebUtilities", "WebEncoders",
            "Base64UrlDecode")
    )
  }
}

module UnverifiedJwtPayloadDecodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof JwtPayloadSegment }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof Base64DecodeSink }
}

module UnverifiedJwtPayloadDecodeFlow = TaintTracking::Global<UnverifiedJwtPayloadDecodeConfig>;

from UnverifiedJwtPayloadDecodeFlow::PathNode source, UnverifiedJwtPayloadDecodeFlow::PathNode sink
where UnverifiedJwtPayloadDecodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "JWT payload segment from $@ is base64-decoded without verifying the token signature; its claims can be forged.",
  source.getNode(), "this token"
