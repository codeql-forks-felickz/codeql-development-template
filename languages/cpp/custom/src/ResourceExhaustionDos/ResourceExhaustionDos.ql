/**
 * @name Resource exhaustion and denial of service
 * @description Untrusted values that control loop bounds, assertions or recursion
 *              depth, unbounded or infinite recursion, and locks that are never
 *              released can let an attacker exhaust CPU, stack or threads and
 *              deny service.
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
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.controlflow.Guards

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
    exists(Expr update |
      update.getEnclosingStmt().getParentStmt*() = loop and
      (
        update.(CrementOperation).getOperand().(VariableAccess).getTarget() = v or
        update.(AssignArithmeticOperation).getLValue().(VariableAccess).getTarget() = v
      )
    )
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

/** Holds if `f` recurses on parameter `p`, i.e. it passes a value derived from `p` to itself. */
predicate recursesOnParameter(Function f, Parameter p, int i) {
  p = f.getParameter(i) and
  exists(FunctionCall rc |
    rc.getTarget() = f and
    rc.getEnclosingFunction() = f and
    rc.getArgument(i).getAChild*().(VariableAccess).getTarget() = p
  )
}

/** Holds if `f` compares parameter `p` against an upper limit (for example `p > MAX`). */
predicate hasUpperDepthCheck(Function f, Parameter p) {
  p.getFunction() = f and
  exists(RelationalOperation cmp |
    cmp.getEnclosingFunction() = f and
    cmp.getGreaterOperand().(VariableAccess).getTarget() = p
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

/** Holds if `e` reads a variable whose value is bounded above in the basic block of `e`. */
predicate isUpperBounded(Expr e) {
  exists(Variable v, VariableAccess a, GuardCondition g |
    e.(VariableAccess).getTarget() = v and
    a.getTarget() = v and
    (
      g.ensuresLt(a, _, _, e.getBasicBlock(), true)
      or
      g.ensuresLt(a, _, e.getBasicBlock(), true)
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
}

module UntrustedResourceConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FlowSource }

  predicate isSink(DataFlow::Node sink) { taintSink(sink.asExpr(), _) }

  predicate isBarrier(DataFlow::Node node) { isUpperBounded(node.asExpr()) }
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
  exists(Expr arg | arg = call.getArgument(0) |
    arg.(VariableAccess).getTarget() = result or
    arg.(AddressOfExpr).getOperand().(VariableAccess).getTarget() = result
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
