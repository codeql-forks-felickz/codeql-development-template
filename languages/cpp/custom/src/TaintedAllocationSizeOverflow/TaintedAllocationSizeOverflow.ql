/**
 * @name Integer overflow in allocation size from untrusted data
 * @description Multiplying an untrusted count by an element size to compute an
 *              allocation size can wrap around, so that a buffer that is too
 *              small is allocated and later written beyond its end.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id cpp/tainted-allocation-size-overflow
 * @tags security
 *       external/cwe/cwe-680
 *       external/cwe/cwe-190
 *       external/cwe/cwe-131
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import TaintedAllocationSizeOverflow::PathGraph

/**
 * Gets an argument of the allocation `alloc` that determines the allocation
 * size, as written in the source. Unlike `AllocationExpr.getSizeExpr`, this
 * does not strip a `* sizeof(T)` multiplier from the argument.
 */
Expr getAnAllocationSizeArgument(AllocationExpr alloc) {
  exists(AllocationFunction f | f = alloc.(FunctionCall).getTarget() |
    result = alloc.(FunctionCall).getArgument([f.getSizeArg(), f.getSizeMult()])
  )
  or
  result = alloc.(NewArrayExpr).getExtent()
}

/**
 * Holds if `child` contributes to the value of `parent`.
 */
predicate isValueChild(Expr parent, Expr child) {
  exists(CommaExpr comma |
    parent = comma and
    child = comma.getRightOperand()
  )
  or
  exists(Call call, int i |
    parent = call and
    child = call.getArgument(i) and
    not exists(Function target, Parameter parameter |
      target = call.getTarget() and
      target.hasDefinition() and
      parameter = target.getParameter(i) and
      not exists(VariableAccess access |
        access.getTarget() = parameter and
        access.getEnclosingFunction() = target
      )
    )
  )
  or
  exists(ConditionalExpr conditional |
    parent = conditional and
    (child = conditional.getThen() or child = conditional.getElse())
  )
  or
  exists(Assignment assignment |
    parent = assignment and
    child = assignment.getRValue()
  )
  or
  exists(UnaryOperation unary |
    parent = unary and
    child = unary.getOperand()
  )
  or
  exists(BinaryOperation binary |
    parent = binary and
    (child = binary.getLeftOperand() or child = binary.getRightOperand())
  )
  or
  exists(Conversion conversion |
    parent = conversion and
    child = conversion.getExpr()
  )
}

/**
 * Holds if `subExpr` contributes to the value of `sizeExpr`.
 */
predicate isValueSubexpression(Expr sizeExpr, Expr subExpr) {
  sizeExpr = subExpr
  or
  exists(Expr child |
    isValueChild(sizeExpr, child) and
    isValueSubexpression(child, subExpr)
  )
}

/**
 * Holds if `mul` is a multiplication in the size argument of the allocation
 * `alloc`, and range analysis cannot rule out that it wraps around.
 */
predicate overflowingAllocationSize(AllocationExpr alloc, MulExpr mul) {
  isValueSubexpression(getAnAllocationSizeArgument(alloc), mul) and
  convertedExprMightOverflowPositively(mul)
}

module TaintedAllocationSizeOverflowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(MulExpr mul |
      overflowingAllocationSize(_, mul) and
      sink.asExpr() = mul.getAnOperand()
    )
  }

  predicate isBarrierOut(DataFlow::Node node) { isSink(node) }
}

module TaintedAllocationSizeOverflow = TaintTracking::Global<TaintedAllocationSizeOverflowConfig>;

from
  AllocationExpr alloc, MulExpr mul, TaintedAllocationSizeOverflow::PathNode source,
  TaintedAllocationSizeOverflow::PathNode sink, FlowSource src
where
  TaintedAllocationSizeOverflow::flowPath(source, sink) and
  overflowingAllocationSize(alloc, mul) and
  sink.getNode().asExpr() = mul.getAnOperand() and
  src = source.getNode()
select alloc, source, sink,
  "This allocation size is computed by a multiplication that may overflow, using $@.", src,
  "untrusted data (" + src.getSourceType() + ")"
