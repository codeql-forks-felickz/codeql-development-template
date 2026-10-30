/**
 * @name Uncontrolled allocation size from a struct field
 * @description Allocating memory with a size derived from a field of a struct
 *              that was filled with external input (for example by `fread`)
 *              can overflow or allocate arbitrary amounts of memory.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id cpp/uncontrolled-allocation-size-struct-field
 * @tags reliability
 *       security
 *       external/cwe/cwe-190
 *       external/cwe/cwe-789
 */

import cpp
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.rangeanalysis.RangeAnalysisUtils
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.ir.IR
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.security.FlowSources
import UncontrolledAllocationSizeStructField::PathGraph

/**
 * Holds if `alloc` is an allocation, and `sink` is an integral child of it
 * (the same sinks as `cpp/uncontrolled-allocation-size`).
 */
predicate allocSink(HeuristicAllocationExpr alloc, DataFlow::Node sink) {
  exists(Expr e | e = sink.asExpr() |
    e = alloc.getAChild() and
    e.getUnspecifiedType() instanceof IntegralType
  )
}

pragma[inline]
private predicate boundedBitwiseAnd(Expr operand, Expr andExpr) {
  upperBound(operand.getFullyConverted()) < exprMaxVal(andExpr.getFullyConverted())
}

/**
 * Holds if `e` is an arithmetic expression that cannot overflow, or an
 * operation that may greatly reduce the range of possible values. This mirrors
 * the `bounded` predicate used by `cpp/uncontrolled-allocation-size`.
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

/** Gets the variable that holds (or points to) the object accessed by `fa`, if any. */
Variable getQualifierVariable(FieldAccess fa) {
  result = fa.getQualifier().(VariableAccess).getTarget()
}

/**
 * Holds if `fa` reads an integral field of a struct that may have been filled
 * with external input.
 */
predicate integralFieldRead(FieldAccess fa) {
  fa.getUnspecifiedType() instanceof IntegralType and
  not fa.isUsedAsLValue()
}

/**
 * Holds if the field read by `fa` is compared using a relational operator
 * (other than against `0`) through the same qualifier variable somewhere in the
 * enclosing function. This is the field counterpart of `hasUpperBoundsCheck`.
 */
predicate fieldHasUpperBoundsCheck(FieldAccess fa) {
  exists(RelationalOperation oper, FieldAccess check |
    oper.getAnOperand() = check and
    check.getTarget() = fa.getTarget() and
    getQualifierVariable(check) = getQualifierVariable(fa) and
    check.getEnclosingFunction() = fa.getEnclosingFunction() and
    not oper.getAnOperand().getValue() = "0"
  )
}

/**
 * Holds if `node2` reads an integral field of the object whose contents are
 * represented by `node1`. The standard C/C++ taint tracking library does not
 * propagate taint from a whole object (for example, a struct written by
 * `fread(&img, sizeof(img), 1, fp)`) to the individual fields read from it.
 */
predicate structFieldReadStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(FieldAccess fa |
    integralFieldRead(fa) and
    node1.asIndirectExpr() = fa.getQualifier() and
    node2.asExpr() = fa
  )
}

predicate isFlowSource(FlowSource source, string sourceType) { sourceType = source.getSourceType() }

/**
 * A taint-tracking configuration for external input that reaches an
 * allocation size through a field read of a tainted struct.
 *
 * The flow state records whether the path has gone through such a field read,
 * so that results already reported by `cpp/uncontrolled-allocation-size` are
 * not duplicated.
 */
module UncontrolledAllocationSizeStructFieldConfig implements DataFlow::StateConfigSig {
  /** Holds if the path has passed through a struct field read. */
  class FlowState = boolean;

  predicate isSource(DataFlow::Node source, FlowState state) {
    isFlowSource(source, _) and state = false
  }

  predicate isSink(DataFlow::Node sink, FlowState state) { allocSink(_, sink) and state = true }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    structFieldReadStep(node1, node2) and
    state1 = [false, true] and
    state2 = true
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(Expr e | e = node.asExpr() |
      bounded(e)
      or
      e = any(PointerDiffExpr diff).getAnOperand()
      or
      fieldHasUpperBoundsCheck(e)
    )
    or
    exists(Variable checkedVar, Instruction instr | instr = node.asOperand().getDef() |
      readsVariable(instr, checkedVar, _) and
      hasUpperBoundsCheck(checkedVar)
    )
    or
    nodeIsBarrierEquality(node)
    or
    // block flow to inside of identified allocation functions (this flow leads
    // to duplicate results)
    any(HeuristicAllocationFunction f).getAParameter() = node.asParameter()
  }

  Location getASelectedSinkLocation(DataFlow::Node sink) {
    exists(Expr alloc | result = [alloc.getLocation(), sink.getLocation()] | allocSink(alloc, sink))
  }
}

module UncontrolledAllocationSizeStructField =
  TaintTracking::GlobalWithState<UncontrolledAllocationSizeStructFieldConfig>;

from
  Expr alloc, UncontrolledAllocationSizeStructField::PathNode source,
  UncontrolledAllocationSizeStructField::PathNode sink, string taintCause
where
  isFlowSource(source.getNode(), taintCause) and
  UncontrolledAllocationSizeStructField::flowPath(source, sink) and
  allocSink(alloc, sink.getNode())
select alloc, source, sink,
  "This allocation size is derived from a struct field read from $@ and could overflow or allocate arbitrary amounts of memory.",
  source.getNode(), "user input (" + taintCause + ")"
