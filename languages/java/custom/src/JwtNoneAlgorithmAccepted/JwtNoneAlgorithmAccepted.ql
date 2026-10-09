/**
 * @name JWT validator accepts the 'none' algorithm from the token header
 * @description Treating a JSON Web Token (JWT) as valid when its attacker-controlled
 *              'alg' header is 'none' skips signature verification and allows an
 *              attacker to forge arbitrary tokens.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id java/jwt-none-algorithm-accepted
 * @tags security
 *       external/cwe/cwe-347
 */

import java
import semmle.code.java.controlflow.Guards
import semmle.code.java.dataflow.TaintTracking

/** A read of the `alg` entry of a decoded JWT header, such as `header.get("alg")`. */
class JwtAlgHeaderRead extends MethodCall {
  JwtAlgHeaderRead() {
    this.getMethod().getName().matches("get%") and
    this.getNumArgument() = 1 and
    this.getArgument(0).(CompileTimeConstantExpr).getStringValue().toLowerCase() = "alg"
  }
}

/** A compile-time constant string whose value is `none`, ignoring case. */
class NoneAlgorithmLiteral extends CompileTimeConstantExpr {
  NoneAlgorithmLiteral() { this.getStringValue().toLowerCase() = "none" }
}

/** Holds if `eq` is an equality check between `a` and `b`. */
predicate stringEqualityCheck(MethodCall eq, Expr a, Expr b) {
  eq.getMethod().getDeclaringType() instanceof TypeString and
  eq.getMethod().hasName(["equals", "equalsIgnoreCase", "contentEquals"]) and
  a = eq.getQualifier() and
  b = eq.getArgument(0)
  or
  eq.getMethod().hasQualifiedName("java.util", "Objects", "equals") and
  a = eq.getArgument(0) and
  b = eq.getArgument(1)
}

/** Holds if `eq` checks whether the `alg` header value read by `read` is `none`. */
predicate algIsNoneCheck(MethodCall eq, JwtAlgHeaderRead read) {
  exists(Expr x, Expr y | stringEqualityCheck(eq, x, y) or stringEqualityCheck(eq, y, x) |
    x instanceof NoneAlgorithmLiteral and
    TaintTracking::localExprTaint(read, y)
  )
}

from MethodCall eq, JwtAlgHeaderRead read, ReturnStmt ret
where
  algIsNoneCheck(eq, read) and
  ret.getExpr().(BooleanLiteral).getBooleanValue() = true and
  eq.(Guard).controls(ret.getBasicBlock(), true)
select eq,
  "This check treats a JWT as valid without verifying its signature when the $@ is 'none'.", read,
  "token's 'alg' header"
