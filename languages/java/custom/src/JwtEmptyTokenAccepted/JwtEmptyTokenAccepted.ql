/**
 * @name JWT validator accepts a token with no parts
 * @description Treating a JSON Web Token (JWT) as valid when it splits into zero parts
 *              lets an attacker authenticate with a token such as "." that has no
 *              header, payload or signature.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.2
 * @precision high
 * @id java/jwt-empty-token-accepted
 * @tags security
 *       external/cwe/cwe-347
 */

import java
import semmle.code.java.controlflow.Guards
import semmle.code.java.dataflow.DataFlow

/** A call to `String.split` whose result is the parts of a token. */
class TokenSplit extends MethodCall {
  TokenSplit() {
    this.getMethod().getDeclaringType() instanceof TypeString and
    this.getMethod().hasName("split")
  }

  /** Holds if this splits on a literal period, e.g. `"\\."` or `"[.]"`. */
  predicate splitsOnPeriod() {
    this.getArgument(0).(CompileTimeConstantExpr).getStringValue() = ["\\.", "[.]"]
  }
}

/** Holds if `c` reads the `alg` entry of a decoded JWT header, e.g. `header.getString("alg")`. */
predicate readsAlgHeader(Callable c) {
  exists(MethodCall mc |
    mc.getEnclosingCallable() = c and
    mc.getMethod().getName().matches("get%") and
    mc.getNumArgument() = 1 and
    mc.getArgument(0).(CompileTimeConstantExpr).getStringValue().toLowerCase() = "alg"
  )
}

/** Holds if `split` splits a JWT: its enclosing callable reads the `alg` header, or it splits a JWT-named value on periods. */
predicate isJwtSplit(TokenSplit split) {
  readsAlgHeader(split.getEnclosingCallable())
  or
  split.splitsOnPeriod() and
  split.getQualifier().(VarAccess).getVariable().getName().regexpMatch("(?i).*(jwt|token).*")
}

/**
 * Holds if `guard` evaluating to `branch` means that `len`, the length of the
 * parts array, is zero.
 */
predicate zeroPartsCheck(Guard guard, PartsLength len, boolean branch) {
  exists(EqualityTest eq | eq = guard |
    eq.hasOperands(len, any(IntegerLiteral z | z.getIntValue() = 0)) and
    branch = eq.polarity()
  )
  or
  exists(ComparisonExpr cmp, IntegerLiteral k | cmp = guard |
    cmp.getLesserOperand() = len and
    cmp.getGreaterOperand() = k and
    (
      cmp.isStrict() and k.getIntValue() = 1
      or
      not cmp.isStrict() and k.getIntValue() = 0
    ) and
    branch = true
    or
    cmp.getGreaterOperand() = len and
    cmp.getLesserOperand() = k and
    (
      cmp.isStrict() and k.getIntValue() = 0
      or
      not cmp.isStrict() and k.getIntValue() = 1
    ) and
    branch = false
  )
}

/** An access `parts.length` where `parts` comes from a JWT split. */
class PartsLength extends FieldAccess {
  TokenSplit split;

  PartsLength() {
    this.getField() instanceof ArrayLengthField and
    isJwtSplit(split) and
    DataFlow::localExprFlow(split, this.getQualifier())
  }

  /** Gets the split call that produced the parts array. */
  TokenSplit getSplit() { result = split }
}

from Guard guard, PartsLength len, boolean branch, ReturnStmt ret
where
  zeroPartsCheck(guard, len, branch) and
  ret.getExpr().(BooleanLiteral).getBooleanValue() = true and
  guard.controls(ret.getBasicBlock(), branch)
select guard,
  "This check treats a JWT as valid without verifying its signature when $@ has no parts.",
  len.getSplit(), "the split token"
