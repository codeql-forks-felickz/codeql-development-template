/**
 * @name User-controlled loop bound with costly iterations
 * @description A loop whose number of iterations is controlled by a user, and whose body
 *              repeatedly concatenates immutable strings or allocates boxed numbers, lets a
 *              single request consume excessive CPU and memory.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id java/uncontrolled-loop-bound-resource-consumption
 * @tags security
 *       external/cwe/cwe-400
 *       external/cwe/cwe-606
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.controlflow.Guards

/**
 * The largest constant upper bound that is considered small enough to make a loop with
 * costly iterations safe.
 */
int smallBound() { result = 10000 }

/** Holds if `e` is a compile-time constant no larger than `smallBound()`. */
predicate isSmallConstant(Expr e) { e.(CompileTimeConstantExpr).getIntValue() <= smallBound() }

/**
 * Holds if `update` in the body of `loop` creates a new object on every iteration from the
 * previous value of `v`, which is declared outside the loop. `kind` describes the cost.
 */
predicate costlyLoopCarriedUpdate(LoopStmt loop, Variable v, Expr update, string kind) {
  update.getEnclosingStmt().getEnclosingStmt*() = loop.getBody() and
  not exists(LocalVariableDeclExpr decl | decl.getVariable() = v |
    decl.getEnclosingStmt().getEnclosingStmt*() = loop.getBody()
  ) and
  (
    // `s += x` or `s = s + x` on a String: copies the whole string on every iteration.
    v.getType() instanceof TypeString and
    kind = "concatenates immutable strings" and
    (
      update.(AssignAddExpr).getDest() = v.getAnAccess()
      or
      exists(AssignExpr a | a = update |
        a.getDest() = v.getAnAccess() and
        a.getRhs().(AddExpr).getAnOperand() = v.getAnAccess()
      )
    )
    or
    // `sum += i` or `sum++` on a boxed number: allocates a new boxed object on every iteration.
    v.getType() instanceof BoxedType and
    kind = "allocates a boxed " + v.getType().getName() and
    (
      update.(AssignOp).getDest() = v.getAnAccess() or
      update.(UnaryAssignExpr).getOperand() = v.getAnAccess()
    )
  )
}

/** Holds if `conjunct` is the condition or a top-level conjunct of `condition`. */
predicate topLevelConjunct(Expr condition, Expr conjunct) {
  condition = conjunct
  or
  exists(AndLogicalExpr andExpr |
    condition = andExpr and
    topLevelConjunct(andExpr.getAnOperand(), conjunct)
  )
}

/** Holds if the condition of `loop` compares a value against a small constant upper bound. */
predicate hasSmallConstantBound(LoopStmt loop) {
  exists(ComparisonExpr c |
    topLevelConjunct(loop.getCondition(), c) and
    isSmallConstant(c.getGreaterOperand())
  )
}

/**
 * Holds if `guard` checks that `e` is no larger than a small constant when it evaluates to
 * `branch`.
 */
predicate smallUpperBoundGuard(Guard guard, Expr e, boolean branch) {
  exists(ComparisonExpr c | c = guard |
    e = c.getLesserOperand() and isSmallConstant(c.getGreaterOperand()) and branch = true
    or
    e = c.getGreaterOperand() and isSmallConstant(c.getLesserOperand()) and branch = false
  )
}

/**
 * A Commons Lang `NumberUtils` method that converts a string to a number. (The `java.lang`
 * parsing methods are already taint-preserving.)
 */
class NumberUtilsConversionMethod extends Method {
  NumberUtilsConversionMethod() {
    this.getDeclaringType()
        .hasQualifiedName(["org.apache.commons.lang.math", "org.apache.commons.lang3.math"],
          "NumberUtils") and
    this.hasName([
        "toInt", "toLong", "toShort", "toDouble", "toFloat", "createInteger", "createLong"
      ])
  }
}

/** An operand of a comparison in the condition of a loop with costly iterations. */
class CostlyLoopBound extends DataFlow::Node {
  LoopStmt loop;

  CostlyLoopBound() {
    costlyLoopCarriedUpdate(loop, _, _, _) and
    not hasSmallConstantBound(loop) and
    exists(ComparisonExpr c |
      c = loop.getCondition().getAChildExpr*() and
      this.asExpr() = c.getAnOperand() and
      this.getType() instanceof NumericOrCharType
    )
  }

  /** Gets the loop bounded by this node. */
  LoopStmt getLoop() { result = loop }
}

module UncontrolledLoopBoundConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof CostlyLoopBound }

  predicate isBarrier(DataFlow::Node node) {
    node = DataFlow::BarrierGuard<smallUpperBoundGuard/3>::getABarrierNode()
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodCall mc |
      mc.getMethod() instanceof NumberUtilsConversionMethod and
      pred.asExpr() = mc.getArgument(0) and
      succ.asExpr() = mc
    )
  }
}

module UncontrolledLoopBoundFlow = TaintTracking::Global<UncontrolledLoopBoundConfig>;

import UncontrolledLoopBoundFlow::PathGraph

/** Gets the first costly update in `loop`, and its `kind`. */
Expr firstCostlyUpdate(LoopStmt loop, string kind) {
  result =
    min(Expr u |
      costlyLoopCarriedUpdate(loop, _, u, _)
    |
      u order by u.getLocation().getStartLine(), u.getLocation().getStartColumn()
    ) and
  costlyLoopCarriedUpdate(loop, _, result, kind)
}

from
  UncontrolledLoopBoundFlow::PathNode source, UncontrolledLoopBoundFlow::PathNode sink, Expr update,
  string kind
where
  UncontrolledLoopBoundFlow::flowPath(source, sink) and
  update = firstCostlyUpdate(sink.getNode().(CostlyLoopBound).getLoop(), kind)
select sink.getNode(), source, sink,
  "The number of iterations of this loop depends on a $@, and each iteration $@.", source.getNode(),
  "user-provided value", update, kind
