/**
 * @name Resource exhaustion and denial of service
 * @description Untrusted values that control loop bounds, assertions, recursion
 *              depth, sleep durations or allocation sizes, unbounded or
 *              infinite recursion, and locks that are never released can let
 *              an attacker exhaust CPU, memory, stack or threads and deny
 *              service.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id cpp/resource-exhaustion-dos
 * @tags security
 *       external/cwe/cwe-400
 *       external/cwe/cwe-606
 *       external/cwe/cwe-617
 *       external/cwe/cwe-667
 *       external/cwe/cwe-674
 *       external/cwe/cwe-789
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.ir.internal.ASTValueNumbering
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.rangeanalysis.RangeAnalysisUtils
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis

/**
 * A constant recursion depth that is considered unbounded in practice
 * (for example `UINT_MAX`).
 */
bindingset[v]
predicate isHugeDepth(float v) { v >= 1048576.0 }

/**
 * Holds if `loop` updates `v` (for example `i++` or `i += 1`) and
 * `cmp` is a relational comparison in the loop condition that compares
 * `v` against `bound`, so that `bound` determines the number of iterations.
 */
predicate loopBound(Loop loop, RelationalOperation cmp, Expr bound) {
  cmp.getParent*() = loop.getCondition() and
  bound = cmp.getGreaterOperand() and
  exists(Variable v |
    cmp.getLesserOperand().(VariableAccess).getTarget() = v and
    not bound.(VariableAccess).getTarget() = v and
    not exists(RelationalOperation cap |
      cap != cmp and
      cap.getParent*() = loop.getCondition() and
      cap.getLesserOperand().(VariableAccess).getTarget() = v and
      hasFiniteUpperBound(cap.getGreaterOperand())
    ) and
    exists(Expr update |
      update.getEnclosingStmt().getParentStmt*() = loop and
      (
        update.(CrementOperation).getOperand().(VariableAccess).getTarget() = v or
        update.(AssignArithmeticOperation).getLValue().(VariableAccess).getTarget() = v
      )
    )
  )
}

/** Holds if `e` has an independently established finite upper bound. */
predicate hasFiniteUpperBound(Expr e) {
  upperBound(e.getFullyConverted()) < typeUpperBound(e.getFullyConverted().getType())
}

/** Holds if `e` is known to be nonnegative where it is used. */
predicate isNonnegativeAt(Expr e) {
  lowerBound(e) >= 0.0
  or
  exists(VariableAccess a, GuardCondition g |
    a.getTarget() = e.(VariableAccess).getTarget() and
    globalValueNumber(a) = globalValueNumber(e) and
    g.ensuresLt(a, 0, e.getBasicBlock(), false)
  )
}

/** Holds if `e` is evaluated as part of the condition of an `assert` macro. */
predicate assertedExpr(Expr e) {
  exists(MacroInvocation mi |
    mi.getMacroName() = "assert" and
    e = mi.getAnExpandedElement() and
    not e.isConstant() and
    (e instanceof VariableAccess or e instanceof Call)
  )
}

/** Holds if `arg` updates `p` additively. */
predicate additiveRecursionArgument(Expr arg, Parameter p) {
  exists(AddExpr add |
    arg.getAChild*() = add and
    (
      add.getLeftOperand().(VariableAccess).getTarget() = p and
      add.getRightOperand().isConstant()
      or
      add.getRightOperand().(VariableAccess).getTarget() = p and
      add.getLeftOperand().isConstant()
    )
  )
  or
  exists(SubExpr sub |
    arg.getAChild*() = sub and
    sub.getLeftOperand().(VariableAccess).getTarget() = p and
    sub.getRightOperand().isConstant()
  )
  or
  exists(CrementOperation crement |
    arg.getAChild*() = crement and
    crement.getOperand().(VariableAccess).getTarget() = p
  )
}

/** Holds if `f` recurses on parameter `p` using an additive update. */
predicate recursesOnParameter(Function f, Parameter p, int i) {
  p = f.getParameter(i) and
  exists(FunctionCall rc |
    rc.getTarget() = f and
    rc.getEnclosingFunction() = f and
    additiveRecursionArgument(rc.getArgument(i), p)
  )
}

/**
 * Holds if the value passed to a recursive call is bounded to a practical
 * depth, rather than only having a base-case check.
 */
predicate hasUpperDepthCheck(Function f, Parameter p) {
  p.getFunction() = f and
  not exists(FunctionCall rc, int i |
    rc.getTarget() = f and
    rc.getEnclosingFunction() = f and
    additiveRecursionArgument(rc.getArgument(i), p) and
    not exists(float ub |
      ub = upperBound(rc.getArgument(i).getFullyConverted()) and
      ub < 1048576.0
    )
  )
}

/**
 * Holds if `arg` is passed from outside of `f` as the recursion depth of `f`,
 * and `f` does not limit that depth.
 */
predicate unboundedRecursionDepth(FunctionCall call, Expr arg, Function f) {
  exists(Parameter p, int i |
    call.getTarget() = f and
    recursesOnParameter(f, p, i) and
    not hasUpperDepthCheck(f, p) and
    not call.getEnclosingFunction() = f and
    arg = call.getArgument(i)
  )
}

/** Holds if `e` is a signed value that reaches an unsigned resource sink. */
predicate needsNonnegativeBound(Expr e) {
  not e.getType().getUnderlyingType().(IntegralType).isUnsigned() and
  (
    sleepDuration(e) or
    allocationSize(e) or
    loopBound(_, _, e) and
    e.getFullyConverted().getType().getUnderlyingType().(IntegralType).isUnsigned()
  )
}

/** Holds if `e` reads a value bounded above in its basic block without reassignment. */
predicate isUpperBounded(Expr e) {
  exists(Variable v, VariableAccess a, GuardCondition g |
    e.(VariableAccess).getTarget() = v and
    a.getTarget() = v and
    globalValueNumber(a) = globalValueNumber(e) and
    (
      exists(Expr limit |
        g.ensuresLt(a, limit, _, e.getBasicBlock(), true) and
        hasFiniteUpperBound(limit)
      )
      or
      g.ensuresLt(a, _, e.getBasicBlock(), true)
    )
  )
}

/** Holds if `e` is the duration argument of a call that suspends the current thread. */
predicate sleepDuration(Expr e) {
  exists(FunctionCall call |
    call.getTarget().hasGlobalName(["sleep", "usleep", "Sleep", "SleepEx"]) and
    e = call.getArgument(0)
  )
}

/**
 * Holds if `e` is the size of a heap allocation and reads a variable that is
 * compared with a relational operator somewhere, but not against an upper
 * limit. `cpp/uncontrolled-allocation-size` treats any such comparison
 * (for example the lower-bound check `n > strlen(s)`) as a sanitizer, so this
 * query reports only those allocations and leaves the rest to that query.
 */
predicate allocationSize(Expr e) {
  exists(AllocationExpr alloc, Variable v |
    e = alloc.getSizeExpr() and
    e.(VariableAccess).getTarget() = v and
    exists(RelationalOperation cmp |
      cmp.getAnOperand().(VariableAccess).getTarget() = v and
      not cmp.getAnOperand().getValue() = "0"
    )
  )
}

/** The kinds of untrusted-input sinks that this query reports. */
predicate taintSink(Expr e, string kind) {
  loopBound(_, _, e) and kind = "loop bound"
  or
  assertedExpr(e) and kind = "assertion"
  or
  unboundedRecursionDepth(_, e, _) and kind = "recursion depth"
  or
  sleepDuration(e) and kind = "sleep duration"
  or
  allocationSize(e) and kind = "allocation size"
}

module UntrustedResourceConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FlowSource }

  predicate isSink(DataFlow::Node sink) { taintSink(sink.asExpr(), _) }

  predicate isBarrier(DataFlow::Node node) {
    not assertedExpr(node.asExpr()) and
    isUpperBounded(node.asExpr()) and
    (not needsNonnegativeBound(node.asExpr()) or isNonnegativeAt(node.asExpr()))
  }
}

module UntrustedResourceFlow = TaintTracking::Global<UntrustedResourceConfig>;

/**
 * Holds if `n` can be reached from the entry of `f` without first passing
 * through a call from `f` to itself.
 */
predicate reachableWithoutRecursion(Function f, ControlFlowNode n) {
  n = f.getEntryPoint()
  or
  exists(ControlFlowNode pred |
    reachableWithoutRecursion(f, pred) and
    not pred.(FunctionCall).getTarget() = f and
    n = pred.getASuccessor()
  )
}

/**
 * Holds if `call` is a self-call in `f` and every path through `f` reaches a
 * self-call, so `f` can never return normally.
 */
predicate infiniteRecursion(FunctionCall call, Function f) {
  call.getTarget() = f and
  call.getEnclosingFunction() = f and
  reachableWithoutRecursion(f, call) and
  not reachableWithoutRecursion(f, f)
}

/** A call that acquires a lock. */
class LockCall extends FunctionCall {
  LockCall() {
    this.getTarget()
        .hasGlobalName([
            "pthread_mutex_lock", "pthread_rwlock_rdlock", "pthread_rwlock_wrlock",
            "pthread_spin_lock", "mtx_lock", "EnterCriticalSection", "AcquireSRWLockExclusive",
            "AcquireSRWLockShared", "stdThreadLockAcquire"
          ])
  }
}

/** A call that releases a lock. */
class UnlockCall extends FunctionCall {
  UnlockCall() {
    this.getTarget()
        .hasGlobalName([
            "pthread_mutex_unlock", "pthread_rwlock_unlock", "pthread_spin_unlock", "mtx_unlock",
            "LeaveCriticalSection", "ReleaseSRWLockExclusive", "ReleaseSRWLockShared",
            "stdThreadLockRelease"
          ])
  }
}

/** Gets the function-local lock variable referenced by the first argument of `call`. */
LocalVariable lockVariable(FunctionCall call) {
  exists(AddressOfExpr arg |
    arg = call.getArgument(0) and
    arg.getOperand().(VariableAccess).getTarget() = result and
    not result.getType().getUnderlyingType() instanceof PointerType
  )
}

/** Gets a source-code element that represents the flow source `source`. */
Locatable sourceElement(DataFlow::Node source) {
  result = source.asExpr()
  or
  not exists(source.asExpr()) and
  (
    result = source.asDefiningArgument()
    or
    not exists(source.asDefiningArgument()) and
    (result = source.asIndirectExpr() or result = source.asParameter(_))
  )
}

from Element e, string msg, Locatable ref, string refText
where
  exists(DataFlow::Node source, DataFlow::Node sink, string kind |
    UntrustedResourceFlow::flow(source, sink) and
    taintSink(sink.asExpr(), kind) and
    e = sink.asExpr() and
    ref = sourceElement(source) and
    refText = source.(FlowSource).getSourceType() and
    (
      kind = "assertion" and
      msg = "This assertion depends on $@, so an attacker can make it fail and abort the process."
      or
      kind != "assertion" and
      msg = "This " + kind + " depends on $@ without an upper limit, which can exhaust resources."
    )
  )
  or
  exists(Function f |
    infiniteRecursion(e, f) and
    msg = "This call makes $@ recurse infinitely, which exhausts the stack." and
    ref = f and
    refText = f.getName()
  )
  or
  exists(Function f, Expr arg |
    unboundedRecursionDepth(e, arg, f) and
    isHugeDepth(arg.getValue().toFloat()) and
    msg =
      "This call sets the recursion depth of $@ to " + arg.getValue() +
        " without an upper limit, which can exhaust the stack." and
    ref = f and
    refText = f.getName()
  )
  or
  exists(LocalVariable v |
    v = lockVariable(e) and
    e instanceof LockCall and
    not exists(UnlockCall u |
      u.getEnclosingFunction() = e.(LockCall).getEnclosingFunction() and v = lockVariable(u)
    ) and
    msg = "The lock $@ is acquired here but never released, which can deadlock other threads." and
    ref = v and
    refText = v.getName()
  )
select e, msg, ref, refText
