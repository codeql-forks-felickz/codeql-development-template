/**
 * @name JWT parsed after its signature was stripped
 * @description Removing the signature from a JSON Web Token (JWT) and parsing it as an
 *              unsigned token means the claims are trusted without any signature check,
 *              so an attacker can forge them.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.2
 * @precision high
 * @id java/jwt-signature-stripped
 * @tags security
 *       external/cwe/cwe-347
 */

import java
import semmle.code.java.dataflow.TaintTracking

/** A call to a JJWT `JwtParser` method that parses an unsigned (unprotected) token. */
class UnsignedJwtParse extends MethodCall {
  UnsignedJwtParse() {
    exists(Method m | m = this.getMethod() |
      m.getDeclaringType().getAnAncestor().hasQualifiedName("io.jsonwebtoken", "JwtParser") and
      (
        m.hasName([
            "parseClaimsJwt", "parsePlaintextJwt", "parseUnsecuredClaims", "parseUnsecuredContent"
          ])
        or
        m.hasName("parse") and m.getNumberOfParameters() = 1
      )
    )
  }
}

/** Holds if `a` reads element `i` of an array produced by `String.split`. */
private predicate splitPart(ArrayAccess a, int i) {
  i = a.getIndexExpr().(IntegerLiteral).getIntValue() and
  exists(MethodCall split |
    split.getMethod().getDeclaringType() instanceof TypeString and
    split.getMethod().hasName("split") and
    DataFlow::localExprFlow(split, a.getArray())
  )
}

/**
 * An expression that rebuilds a JWT without its signature: either a string
 * concatenation of split parts 0 and 1 that never includes part 2, or
 * `token.substring(0, token.lastIndexOf(...) ...)`.
 */
class SignatureStrippingExpr extends Expr {
  SignatureStrippingExpr() {
    this instanceof AddExpr and
    not this.getParent() instanceof AddExpr and
    splitPart(this.getAChildExpr*(), 0) and
    splitPart(this.getAChildExpr*(), 1) and
    not exists(int i | splitPart(this.getAChildExpr*(), i) and i >= 2)
    or
    exists(MethodCall sub | sub = this |
      sub.getMethod().getDeclaringType() instanceof TypeString and
      sub.getMethod().hasName("substring") and
      sub.getArgument(0).(IntegerLiteral).getIntValue() = 0 and
      sub.getArgument(1).getAChildExpr*().(MethodCall).getMethod().hasName("lastIndexOf")
    )
  }
}

from SignatureStrippingExpr strip, UnsignedJwtParse parse
where TaintTracking::localExprTaint(strip, parse.getArgument(0))
select parse, "This parses a JWT as unsigned after $@, so its claims are never verified.", strip,
  "its signature was removed"
