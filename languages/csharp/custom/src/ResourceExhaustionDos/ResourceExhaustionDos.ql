/**
 * @name Uncontrolled resource consumption from user-provided value
 * @description Using a user-provided value as a loop bound or allocation size without
 *              checking it against an upper limit allows an attacker to exhaust CPU or
 *              memory, leading to a denial of service.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id cs/resource-exhaustion-dos
 * @tags security
 *       external/cwe/cwe-400
 *       external/cwe/cwe-606
 *       external/cwe/cwe-770
 *       external/cwe/cwe-789
 */

import csharp
import semmle.code.csharp.security.dataflow.flowsources.FlowSources
import semmle.code.csharp.controlflow.Guards

/**
 * Holds if `v` is incremented (`up = true`) or decremented (`up = false`) inside `loop`,
 * including in the loop condition or the update clause of a `for` loop.
 */
predicate updatedInLoop(LocalScopeVariable v, LoopStmt loop, boolean up) {
  exists(Expr update |
    update.getEnclosingStmt().getParent*() = loop or
    loop.getCondition().getAChildExpr*() = update
  |
    update.(IncrementOperation).getOperand() = v.getAnAccess() and up = true
    or
    update.(AssignAddExpr).getLeftOperand() = v.getAnAccess() and up = true
    or
    update.(DecrementOperation).getOperand() = v.getAnAccess() and up = false
    or
    update.(AssignSubExpr).getLeftOperand() = v.getAnAccess() and up = false
  )
}

/** A sink for uncontrolled resource consumption. */
abstract class ResourceExhaustionSink extends DataFlow::ExprNode {
  /** Gets a description of how the value is used. */
  abstract string getDescription();
}

/**
 * The upper bound of a loop condition, for example `n` in `for (i = 0; i < n; i++)`, or
 * the counter of a count-down loop, for example `n` in `while (n > 0) { n--; }`.
 */
class LoopBoundSink extends ResourceExhaustionSink {
  LoopBoundSink() {
    exists(LoopStmt loop, RelationalOperation cmp |
      cmp = loop.getCondition().getAChildExpr*() and
      (
        // Counting up towards the bound.
        this.getExpr() = cmp.getGreaterOperand() and
        exists(LocalScopeVariable counter |
          (
            cmp.getLesserOperand() = counter.getAnAccess()
            or
            cmp.getLesserOperand().(IncrementOperation).getOperand() = counter.getAnAccess()
          ) and
          updatedInLoop(counter, loop, true)
        )
        or
        // Counting down from the bound.
        exists(LocalScopeVariable counter |
          this.getExpr() = cmp.getGreaterOperand() and
          this.getExpr() = counter.getAnAccess() and
          updatedInLoop(counter, loop, false)
        )
        or
        exists(LocalScopeVariable counter, DecrementOperation decrement |
          cmp.getGreaterOperand() = decrement and
          this.getExpr() = decrement.getOperand() and
          decrement.getOperand() = counter.getAnAccess() and
          updatedInLoop(counter, loop, false)
        )
      )
    )
  }

  override string getDescription() { result = "loop bound" }
}

/**
 * The size of an allocation, such as the length of an array, the initial capacity of a
 * collection, or the number of elements to generate.
 */
class AllocationSizeSink extends ResourceExhaustionSink {
  AllocationSizeSink() {
    this.getExpr() = any(ArrayCreation ac).getALengthArgument()
    or
    exists(ObjectCreation oc |
      oc.getObjectType().getNamespace().getFullName() =
        [
          "System.Collections", "System.Collections.Generic", "System.Collections.Concurrent",
          "System.Text", "System.IO"
        ] and
      this.getExpr() = oc.getArgumentForName("capacity")
    )
    or
    exists(ObjectCreation oc |
      oc.getObjectType() instanceof StringType and
      this.getExpr() = oc.getArgumentForName("count")
    )
    or
    exists(MethodCall mc |
      mc.getTarget()
          .getUnboundDeclaration()
          .hasFullyQualifiedName("System.Linq", "Enumerable", ["Repeat`1", "Range"]) and
      this.getExpr() = mc.getArgumentForName("count")
    )
  }

  override string getDescription() { result = "allocation size" }
}

/**
 * Holds if `g` checks that `e` is bounded from above when `g` evaluates to `v`, for
 * example `e <= 100` evaluating to `true` or `e > 100` evaluating to `false`.
 *
 * Loop conditions are excluded, since exiting `for (i = 0; i < n; i++)` does not
 * bound `n`.
 */
predicate upperBoundCheck(Guard g, Expr e, GuardValue v) {
  not g = any(LoopStmt loop).getCondition().getAChildExpr*() and
  (
    e = g.(RelationalOperation).getLesserOperand() and v.asBooleanValue() = true
    or
    e = g.(RelationalOperation).getGreaterOperand() and v.asBooleanValue() = false
  )
}

class ClampBound extends DataFlow::ExprNode {
  ClampBound() {
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("System", "Math", "Min") and
      this.getExpr() = mc.getAnArgument()
      or
      mc.getTarget().hasFullyQualifiedName("System", "Math", "Clamp") and
      this.getExpr() = mc.getArgumentForName("max")
    )
  }
}

module ClampBoundConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof ClampBound }
}

module ClampBoundFlow = TaintTracking::Global<ClampBoundConfig>;

predicate isIndependentClampBound(Expr bound) {
  bound.hasValue() or not ClampBoundFlow::flowToExpr(bound)
}

/** A value that is clamped from above, for example `Math.Min(n, 100)`. */
class ClampBarrier extends DataFlow::ExprNode {
  ClampBarrier() {
    exists(MethodCall mc |
      this.getExpr() = mc and
      (
        mc.getTarget().hasFullyQualifiedName("System", "Math", "Min") and
        exists(Expr bound | bound = mc.getAnArgument() | isIndependentClampBound(bound))
        or
        mc.getTarget().hasFullyQualifiedName("System", "Math", "Clamp") and
        isIndependentClampBound(mc.getArgumentForName("max"))
      )
    )
  }
}

module ResourceExhaustionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof ResourceExhaustionSink }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodCall mc |
      node1.asExpr() = mc.getAnArgument() and
      node2.asExpr() = mc and
      mc.getTarget().hasFullyQualifiedName("System", "Math", ["Min", "Clamp"])
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    node = DataFlow::BarrierGuard<upperBoundCheck/3>::getABarrierNode() or
    node instanceof ClampBarrier
  }
}

module ResourceExhaustion = TaintTracking::Global<ResourceExhaustionConfig>;

import ResourceExhaustion::PathGraph

from ResourceExhaustion::PathNode source, ResourceExhaustion::PathNode sink
where ResourceExhaustion::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This " + sink.getNode().(ResourceExhaustionSink).getDescription() +
    " depends on a $@ without an upper bound check.", source.getNode(), "user-provided value"
