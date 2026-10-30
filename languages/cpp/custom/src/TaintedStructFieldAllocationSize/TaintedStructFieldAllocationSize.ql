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
 * Holds if taint flows from a struct (or union) whose contents are tainted as a whole, for
 * example because the struct was filled by `fread(&s, sizeof(s), 1, fp)`, to a read of one of
 * its fields `s.f` or `p->f`. For fields that are themselves aggregates, taint also flows to the
 * contents of the field so that nested reads such as `s.inner.f` are covered.
 *
 * The IR taint tracking library does not have this step: a source that taints the whole
 * object does not carry any field content, so field reads are never reached.
 */
predicate aggregateToFieldStep(DataFlow::Node n1, DataFlow::Node n2) {
  exists(FieldAccess fa |
    n1.asIndirectExpr(1) = fa.getQualifier() and
    (
      n2.asExpr() = fa
      or
      fa.getUnspecifiedType() instanceof Class and
      n2.asIndirectExpr(1) = fa
    )
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
    checked.getTarget() = fa.getTarget() and
    checked.getEnclosingFunction() = fa.getEnclosingFunction() and
    not oper.getAnOperand().getValue() = "0"
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
