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
import semmle.code.java.dataflow.DataFlow

/** Local aliases and fluent steps specifically on JJWT parser builders. */
private predicate builderStep(Expr source, Expr sink) {
  DataFlow::localExprFlow(source, sink)
  or
  exists(MethodCall call |
    source = call.getQualifier() and
    sink = call and
    call.getMethod()
        .getDeclaringType()
        .getAnAncestor()
        .hasQualifiedName("io.jsonwebtoken", "JwtParserBuilder") and
    call.getType().(RefType).getAnAncestor().hasQualifiedName("io.jsonwebtoken", "JwtParserBuilder")
  )
}

/** The parser is built from a builder explicitly configured to accept unsecured JWTs. */
private predicate hasUnsecuredParser(MethodCall parse) {
  exists(MethodCall unsecured, MethodCall build |
    unsecured
        .getMethod()
        .getDeclaringType()
        .getAnAncestor()
        .hasQualifiedName("io.jsonwebtoken", "JwtParserBuilder") and
    unsecured.getMethod().hasName("unsecured") and
    build
        .getMethod()
        .getDeclaringType()
        .getAnAncestor()
        .hasQualifiedName("io.jsonwebtoken", "JwtParserBuilder") and
    build.getMethod().hasName("build") and
    builderStep*(unsecured.getQualifier(), build.getQualifier()) and
    DataFlow::localExprFlow(build, parse.getQualifier())
  )
}

/** A call to a JJWT `JwtParser` method that parses an unsigned (unprotected) token. */
class UnsignedJwtParse extends MethodCall {
  UnsignedJwtParse() {
    exists(Method m | m = this.getMethod() |
      m.getDeclaringType().getAnAncestor().hasQualifiedName("io.jsonwebtoken", "JwtParser") and
      (
        m.hasName(["parseClaimsJwt", "parsePlaintextJwt"])
        or
        m.hasName(["parseUnsecuredClaims", "parseUnsecuredContent"]) and hasUnsecuredParser(this)
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
 * concatenation of split parts 0 and 1 that never includes a later part, or
 * `token.substring(0, token.lastIndexOf(...) ...)`.
 */
class SignatureStrippingExpr extends Expr {
  SignatureStrippingExpr() {
    this instanceof AddExpr and
    not this.getParent() instanceof AddExpr and
    splitPart(this.getAChildExpr*(), 0) and
    splitPart(this.getAChildExpr*(), 1) and
    not exists(ArrayAccess part, int i |
      splitPart(part, i) and
      i >= 2 and
      DataFlow::localExprFlow(part, this.getAChildExpr*())
    )
    or
    exists(MethodCall sub, MethodCall last | sub = this |
      sub.getMethod().getDeclaringType() instanceof TypeString and
      sub.getMethod().hasName("substring") and
      sub.getArgument(0).(IntegerLiteral).getIntValue() = 0 and
      last = sub.getArgument(1).getAChildExpr*() and
      last.getMethod().getDeclaringType() instanceof TypeString and
      last.getMethod().hasName("lastIndexOf") and
      (
        last.getArgument(0).(CharacterLiteral).getValue() = "."
        or
        last.getArgument(0).(CompileTimeConstantExpr).getStringValue() = "."
      ) and
      last.getQualifier().(VarAccess).getVariable() = sub.getQualifier().(VarAccess).getVariable()
    )
  }
}

from SignatureStrippingExpr strip, UnsignedJwtParse parse
where DataFlow::localExprFlow(strip, parse.getArgument(0))
select parse, "This parses a JWT as unsigned after $@, so its claims are never verified.", strip,
  "its signature was removed"
