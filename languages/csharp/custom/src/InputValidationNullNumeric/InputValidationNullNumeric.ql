/**
 * @name Unvalidated user-controlled integer in arithmetic or division
 * @description Using a user-controlled integer as a divisor without a zero check, or as an
 *              operand of an unchecked addition, subtraction or multiplication without a
 *              range check, can cause a `DivideByZeroException` or a silent integer overflow.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id cs/input-validation-null-numeric
 * @tags security
 *       external/cwe/cwe-190
 *       external/cwe/cwe-369
 */

import csharp
import semmle.code.csharp.controlflow.Guards
import semmle.code.csharp.security.dataflow.flowsources.FlowSources

/** Holds if `e` is evaluated in an explicit `checked` context. */
predicate inCheckedContext(Expr e) {
  exists(Element p | p = e.getParent+() |
    p instanceof CheckedExpr or
    p instanceof CheckedStmt
  )
}

/**
 * Holds if `e` is guarded by a condition that compares a structurally equal expression
 * using a comparison of type `kind` (`"any"` for any comparison, `"relational"` for
 * `<`, `<=`, `>` and `>=` only).
 */
bindingset[kind]
predicate isComparedInGuard(Expr e, string kind) {
  exists(Expr sub, ComparisonOperation cmp |
    exists(e.(GuardedExpr).getAGuard(sub, _)) and
    sub = cmp.getAnOperand()
  |
    kind = "any"
    or
    kind = "relational" and cmp instanceof RelationalOperation
  )
}

/** Holds if `e` is the divisor of the integer division or remainder `op` and is not checked for zero. */
predicate isUncheckedDivisor(Expr e, BinaryArithmeticOperation op) {
  (op instanceof DivOperation or op instanceof RemOperation) and
  e = op.getRightOperand() and
  e.getType() instanceof IntegralType and
  op.getType() instanceof IntegralType and
  not isComparedInGuard(e, "any")
}

/**
 * Holds if `e` is an operand of the integer addition, subtraction or multiplication `op` (including compound
 * assignments) that may silently overflow and that is not range checked.
 */
predicate isUncheckedOverflowOperand(Expr e, BinaryArithmeticOperation op) {
  (op instanceof AddOperation or op instanceof SubOperation or op instanceof MulOperation) and
  e = op.getAnOperand() and
  e.getType() instanceof IntegralType and
  op.getType() instanceof IntegralType and
  not inCheckedContext(op) and
  not isComparedInGuard(e, "relational")
}

/**
 * Holds if `pred` is the string argument of an integral `Parse` or `TryParse` call and
 * `succ` is the parsed result. Only some of these methods are modeled by the standard library.
 */
predicate integralParseStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(MethodCall mc, Method m |
    mc.getTarget() = m and
    m.getDeclaringType() instanceof IntegralType and
    pred.asExpr() = mc.getArgument(0)
  |
    m.hasName("Parse") and
    succ.asExpr() = mc
    or
    m.hasName("TryParse") and
    exists(Parameter p |
      p = m.getAParameter() and
      p.isOut() and
      succ.(DataFlow::AssignableDefinitionNode)
          .getDefinition()
          .(AssignableDefinitions::OutRefDefinition)
          .getTargetAccess() = mc.getArgumentForParameter(p)
    )
  )
}

module InputValidationNullNumericConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) {
    isUncheckedDivisor(sink.asExpr(), _) or
    isUncheckedOverflowOperand(sink.asExpr(), _)
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    integralParseStep(pred, succ)
  }

  predicate isBarrier(DataFlow::Node node) {
    // Values clamped to a range are considered validated.
    node.asExpr()
        .(MethodCall)
        .getTarget()
        .hasFullyQualifiedName("System", "Math", ["Min", "Max", "Clamp"])
  }
}

module InputValidationNullNumericFlow = TaintTracking::Global<InputValidationNullNumericConfig>;

import InputValidationNullNumericFlow::PathGraph

from
  InputValidationNullNumericFlow::PathNode source, InputValidationNullNumericFlow::PathNode sink,
  BinaryArithmeticOperation op, string message
where
  InputValidationNullNumericFlow::flowPath(source, sink) and
  (
    isUncheckedDivisor(sink.getNode().asExpr(), op) and
    message =
      "This divisor depends on a $@ and is not checked for zero, which may cause a DivideByZeroException."
    or
    isUncheckedOverflowOperand(sink.getNode().asExpr(), op) and
    message =
      "This arithmetic operand depends on a $@ and is not range checked, which may cause an integer overflow."
  )
select sink.getNode(), source, sink, message, source.getNode(), "user-provided value"
