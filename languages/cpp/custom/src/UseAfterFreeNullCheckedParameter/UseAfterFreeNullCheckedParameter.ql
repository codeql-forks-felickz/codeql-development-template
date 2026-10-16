/**
 * @name Use after free through null-checked callee parameter
 * @description A freed pointer is passed to a function that dereferences the
 *              corresponding parameter whenever it is non-null. A freed pointer
 *              is not null, so the callee accesses released memory.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 9.3
 * @precision high
 * @id cpp/custom/use-after-free-null-checked-parameter
 * @tags reliability
 *       security
 *       external/cwe/cwe-416
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.controlflow.Dominance
import semmle.code.cpp.security.flowafterfree.FlowAfterFree
import semmle.code.cpp.security.flowafterfree.UseAfterFree

/**
 * Holds if the pointer parameter `p` is never reassigned and never has its
 * address taken, so every access to `p` reads the value passed by the caller.
 */
predicate isUnmodifiedPointerParameter(Parameter p) {
  p.getUnspecifiedType() instanceof PointerType and
  not exists(Assignment a | a.getLValue() = p.getAnAccess()) and
  not exists(CrementOperation op | op.getOperand() = p.getAnAccess()) and
  not exists(AddressOfExpr ao | ao.getOperand() = p.getAnAccess())
}

/**
 * Holds if parameter `i` of `f` is dereferenced on every path through `f` on
 * which the parameter is non-null. For example:
 * ```
 * void printLine(const char *line) {
 *   if (line != NULL) {
 *     printf("%s\n", line);
 *   }
 * }
 * ```
 * The standard `cpp/use-after-free` query only treats a parameter as a use if
 * the dereference post-dominates the function entry, which is not the case
 * when the dereference is guarded by a null check.
 */
predicate isDereferencedWhenNonNull(Function f, int i) {
  exists(Parameter p, GuardCondition g, BasicBlock nonNull, VariableAccess use |
    p = f.getParameter(i) and
    isUnmodifiedPointerParameter(p) and
    // The null check is evaluated on every call to `f`.
    bbPostDominates(g.(Expr).getBasicBlock(), f.getEntryPoint().getBasicBlock()) and
    // `nonNull` is the branch taken when the parameter is not null.
    nonNull = g.(Expr).getBasicBlock().getASuccessor() and
    g.ensuresEq(p.getAnAccess(), 0, nonNull, false) and
    // The parameter is always dereferenced on that branch.
    use = p.getAnAccess() and
    isUse0(use) and
    bbPostDominates(use.getBasicBlock(), nonNull)
  )
}

/**
 * Holds if `e` is passed to a function that dereferences it whenever it is
 * non-null, and `e` is not already a use reported by `cpp/use-after-free`.
 */
predicate isNullCheckedParameterUse(DataFlow::Node n, Expr e) {
  exists(FunctionCall call, int i |
    isDereferencedWhenNonNull(call.getTarget(), i) and
    e = call.getArgument(i) and
    n.asExpr() = e and
    not isUse(_, e)
  )
}

module UseAfterFreeNullCheckedParam implements FlowFromFreeParamSig {
  predicate isSink = isNullCheckedParameterUse/2;

  predicate isExcluded = isExcludedMmFreePageFromMdl/2;

  predicate sourceSinkIsRelated = defaultSourceSinkIsRelated/2;
}

module UseAfterFreeNullCheckedTrace = FlowFromFree<UseAfterFreeNullCheckedParam>;

import UseAfterFreeNullCheckedTrace::PathGraph

from
  UseAfterFreeNullCheckedTrace::PathNode source, UseAfterFreeNullCheckedTrace::PathNode sink,
  DeallocationExpr dealloc, FunctionCall call
where
  UseAfterFreeNullCheckedTrace::flowPath(source, sink) and
  isFree(source.getNode(), _, _, dealloc) and
  sink.getNode().asExpr() = call.getAnArgument()
select sink.getNode(), source, sink,
  "Memory may have been previously freed by $@ and is dereferenced by $@ when non-null.", dealloc,
  dealloc.toString(), call.getTarget(), call.getTarget().getName()
