/**
 * @name Uncontrolled allocation size from struct field
 * @description Allocating memory with a size computed from the fields of a struct that was
 *              filled from user input (for example by `fread` or `recv`) can underflow or
 *              overflow and allocate an unexpected amount of memory.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id cpp/uncontrolled-allocation-size-struct-field
 * @tags reliability
 *       security
 *       external/cwe/cwe-190
 *       external/cwe/cwe-191
 *       external/cwe/cwe-789
 */

import cpp
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.rangeanalysis.RangeAnalysisUtils
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.ir.IR
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.security.FlowSources
import TaintedStructFieldAllocationSize::PathGraph

/*
 * The source, sink and barrier predicates below mirror the stock
 * `cpp/uncontrolled-allocation-size` query (`Security/CWE/CWE-190/TaintedAllocationSize.ql`
 * and `Bounded.qll` in `codeql/cpp-queries`), which cannot be imported from a library pack.
 */

pragma[inline]
private predicate boundedBitwiseAnd(Expr operand, Expr andExpr) {
  upperBound(operand.getFullyConverted()) < exprMaxVal(andExpr.getFullyConverted())
}

/**
 * Holds if `e` is an arithmetic expression that cannot overflow, or if `e` is an operation that
 * may greatly reduce the range of possible values.
 */
predicate bounded(Expr e) {
  (
    e instanceof UnaryArithmeticOperation or
    e instanceof BinaryArithmeticOperation or
    e instanceof AssignArithmeticOperation
  ) and
  not convertedExprMightOverflow(e)
  or
  e instanceof RemExpr
  or
  e instanceof DivExpr
  or
  e instanceof RShiftExpr
  or
  exists(BitwiseAndExpr andExpr |
    e = andExpr and boundedBitwiseAnd(andExpr.getAnOperand(), andExpr)
  )
  or
  e = any(AssignRemExpr rem).getLValue()
  or
  e = any(AssignDivExpr div).getLValue()
  or
  e = any(AssignRShiftExpr div).getLValue()
  or
  exists(AssignAndExpr andExpr |
    e = andExpr.getLValue() and boundedBitwiseAnd(andExpr.getRValue(), andExpr)
  )
}

/**
 * Holds if `alloc` is an allocation, and `sink` is a child of it that is a
 * taint sink.
 */
predicate allocSink(HeuristicAllocationExpr alloc, DataFlow::Node sink) {
  exists(Expr e | e = sink.asExpr() |
    e = alloc.getAChild() and
    e.getUnspecifiedType() instanceof IntegralType
  )
}

predicate readsVariable(LoadInstruction load, Variable var, IRBlock bb) {
  load.getSourceAddress().(VariableAddressInstruction).getAstVariable() = var and
  bb = load.getBlock()
}

predicate hasUpperBoundsCheck(Variable var) {
  exists(RelationalOperation oper, VariableAccess access |
    oper.getAnOperand() = access and
    access.getTarget() = var and
    // Comparing to 0 is not an upper bound check
    not oper.getAnOperand().getValue() = "0"
  )
}

predicate variableEqualityCheckedInBlock(Variable checkedVar, IRBlock bb) {
  exists(Operand access |
    readsVariable(access.getDef(), checkedVar, _) and
    any(IRGuardCondition guard).ensuresEq(access, _, _, bb, true)
  )
}

predicate nodeIsBarrierEquality(DataFlow::Node node) {
  exists(Variable checkedVar, Instruction instr, IRBlock bb |
    instr = node.asOperand().getDef() and
    readsVariable(instr, checkedVar, bb) and
    variableEqualityCheckedInBlock(checkedVar, bb)
  )
}

/** Holds if `node` is a barrier in the stock `cpp/uncontrolled-allocation-size` query. */
predicate isStockBarrier(DataFlow::Node node) {
  exists(Expr e | e = node.asExpr() |
    bounded(e)
    or
    e = any(PointerDiffExpr diff).getAnOperand()
  )
  or
  exists(Variable checkedVar, Instruction instr | instr = node.asOperand().getDef() |
    readsVariable(instr, checkedVar, _) and
    hasUpperBoundsCheck(checkedVar)
  )
  or
  nodeIsBarrierEquality(node)
  or
  any(HeuristicAllocationFunction f).getAParameter() = node.asParameter()
}

/**
 * Gets the qualifier of `fa`, skipping qualifiers that are themselves reads of embedded
 * (non-pointer) aggregate fields, so that the root of `s.inner.f` is `s`.
 */
Expr rootQualifier(FieldAccess fa) {
  exists(Expr q | q = fa.getQualifier() |
    if q instanceof FieldAccess and q.getUnspecifiedType() instanceof Class
    then result = rootQualifier(q)
    else result = q
  )
}

/**
 * A configuration that tracks the contents written by a flow source (for example the buffer
 * filled by `fread` or `recv`) by value to the root qualifier of a field read.
 *
 * Only value flow is tracked so that an aggregate is treated as attacker controlled only when
 * its contents were written by the source. In particular, this excludes a trusted struct that is
 * merely selected with a tainted index, as in `table[i].f`.
 */
module WholeObjectSourceConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FlowSource }

  predicate isSink(DataFlow::Node sink) { sink.asIndirectExpr(1) = rootQualifier(_) }
}

module WholeObjectSourceFlow = DataFlow::Global<WholeObjectSourceConfig>;

/**
 * Holds if taint flows from a struct (or union) whose contents were written as a whole by a
 * flow source, for example by `fread(&s, sizeof(s), 1, fp)`, to a read of one of its fields
 * `s.f`, `p->f` or `s.inner.f`.
 *
 * The IR taint tracking library does not have this step: a source that taints the whole
 * object does not carry any field content, so field reads are never reached.
 *
 * The step does not apply to a field that has been assigned since the object was written. Taint
 * from the assigned value, as in `s.f = ntohl(s.f)`, is still tracked through the field store.
 */
predicate aggregateToFieldStep(DataFlow::Node n1, DataFlow::Node n2) {
  exists(FieldAccess fa |
    n1.asIndirectExpr(1) = rootQualifier(fa) and
    WholeObjectSourceFlow::flowTo(n1) and
    n2.asExpr() = fa and
    not fieldIsOverwritten(fa)
  )
}

/**
 * Holds if field read `fa` is of a field that is compared against a value other than
 * zero in a relational comparison in the same function, which is treated as an upper
 * bounds check in the same way as the stock query treats variables.
 */
predicate fieldHasUpperBoundsCheck(FieldAccess fa) {
  exists(RelationalOperation oper, FieldAccess checked |
    oper.getAnOperand() = checked and
    sameFieldAccessPath(checked, fa) and
    checked.getEnclosingFunction() = fa.getEnclosingFunction() and
    not oper.getAnOperand().getValue() = "0"
  )
}

/** Holds if `fa1` and `fa2` access the same field path from the same root. */
predicate sameFieldAccessPath(FieldAccess fa1, FieldAccess fa2) {
  fa1.getTarget() = fa2.getTarget() and
  (
    exists(FieldAccess qualifier1, FieldAccess qualifier2 |
      qualifier1 = fa1.getQualifier() and
      qualifier2 = fa2.getQualifier() and
      sameFieldAccessPath(qualifier1, qualifier2)
    )
    or
    exists(VariableAccess qualifier1, VariableAccess qualifier2 |
      qualifier1 = fa1.getQualifier() and
      qualifier2 = fa2.getQualifier() and
      not qualifier1 instanceof FieldAccess and
      not qualifier2 instanceof FieldAccess and
      qualifier1.getTarget() = qualifier2.getTarget()
    )
    or
    fa1.getQualifier() instanceof ThisExpr and
    fa2.getQualifier() instanceof ThisExpr
  )
}

/** Gets the variable that is the direct qualifier of field access `fa`, as in `v.f` or `v->f`. */
Variable qualifierVariable(FieldAccess fa) {
  result = fa.getQualifier().(VariableAccess).getTarget()
}

/**
 * Holds if `asg` assigns field `f` of the object denoted by variable `v`, and that field is
 * read elsewhere in the same function.
 */
predicate fieldOverwrite(Assignment asg, Field f, Variable v) {
  exists(FieldAccess written, FieldAccess read |
    written = asg.getLValue() and
    f = written.getTarget() and
    v = qualifierVariable(written) and
    read != written and
    read.getTarget() = f and
    qualifierVariable(read) = v and
    read.getEnclosingFunction() = asg.getEnclosingFunction()
  )
}

/**
 * Holds if `n` may write the whole object denoted by `v` again, for example a call such as
 * `fread(&v, ...)` or `fread(v, ...)`, or a whole-object assignment such as `v = ...`.
 */
predicate mayRefill(ControlFlowNode n, Variable v) {
  exists(Call call, int i, Expr argument |
    call = n and
    argument = call.getArgument(i) and
    (
      argument.getFullyConverted().getUnspecifiedType() instanceof PointerType
      or
      exists(ReferenceType referenceType |
        referenceType = call.getTarget().getParameter(i).getType() and
        not referenceType.getBaseType().isConst()
      )
    ) and
    argument.getAChild*().(VariableAccess).getTarget() = v
  )
  or
  n.(Assignment).getLValue().(VariableAccess).getTarget() = v
  or
  n.(Assignment).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget() = v
}

/** Holds if `n` is reachable from `asg` along a path that does not pass through `asg` again. */
predicate reachableFromOverwrite(Assignment asg, ControlFlowNode n) {
  fieldOverwrite(asg, _, _) and n = asg.getASuccessor()
  or
  exists(ControlFlowNode mid |
    reachableFromOverwrite(asg, mid) and
    mid != asg and
    n = mid.getASuccessor()
  )
}

/**
 * Holds if `n` is reachable from `asg`, along a path that does not pass through `asg` again,
 * after an operation that may refill the object that `asg` writes a field of.
 */
predicate refilledAfterOverwrite(Assignment asg, ControlFlowNode n) {
  exists(ControlFlowNode refill, Variable v |
    fieldOverwrite(asg, _, v) and
    reachableFromOverwrite(asg, refill) and
    refill != asg and
    mayRefill(refill, v) and
    n = refill.getASuccessor()
  )
  or
  exists(ControlFlowNode mid |
    refilledAfterOverwrite(asg, mid) and
    mid != asg and
    n = mid.getASuccessor()
  )
}

/**
 * Holds if field read `fa` always reads a value assigned by the program after the object was
 * last written as a whole, as in `fread(&s, ...); s.f = 16; malloc(s.f);`.
 */
predicate fieldIsOverwritten(FieldAccess fa) {
  exists(Assignment asg |
    fieldOverwrite(asg, fa.getTarget(), qualifierVariable(fa)) and
    fa != asg.getLValue() and
    dominates(asg, fa) and
    not refilledAfterOverwrite(asg, fa)
  )
}

module StockTaintedAllocationSizeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FlowSource }

  predicate isSink(DataFlow::Node sink) { allocSink(_, sink) }

  predicate isBarrier(DataFlow::Node node) { isStockBarrier(node) }
}

/** The flow computed by the stock `cpp/uncontrolled-allocation-size` query. */
module StockTaintedAllocationSize = TaintTracking::Global<StockTaintedAllocationSizeConfig>;

module TaintedStructFieldAllocationSizeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FlowSource }

  predicate isSink(DataFlow::Node sink) { allocSink(_, sink) }

  predicate isBarrier(DataFlow::Node node) {
    isStockBarrier(node)
    or
    fieldHasUpperBoundsCheck(node.asExpr())
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    aggregateToFieldStep(n1, n2)
  }
}

module TaintedStructFieldAllocationSize =
  TaintTracking::Global<TaintedStructFieldAllocationSizeConfig>;

/** Holds if `alloc` is already reported by the stock `cpp/uncontrolled-allocation-size` query. */
predicate isReportedByStockQuery(Expr alloc) {
  exists(DataFlow::Node sink |
    StockTaintedAllocationSize::flowTo(sink) and
    allocSink(alloc, sink)
  )
}

from
  Expr alloc, TaintedStructFieldAllocationSize::PathNode source,
  TaintedStructFieldAllocationSize::PathNode sink, string taintCause
where
  TaintedStructFieldAllocationSize::flowPath(source, sink) and
  taintCause = source.getNode().(FlowSource).getSourceType() and
  allocSink(alloc, sink.getNode()) and
  not isReportedByStockQuery(alloc)
select alloc, source, sink,
  "This allocation size is derived from a field of a struct filled with $@ and could underflow or overflow, allocating an unexpected amount of memory.",
  source.getNode(), "user input (" + taintCause + ")"
