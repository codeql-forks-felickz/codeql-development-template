/**
 * @name Fuzzer input buffer used as a null-terminated string
 * @description Fuzzer-provided test case buffers are arbitrary binary data with
 *              an explicit length and are not null-terminated. Passing them to
 *              functions that expect a null-terminated string reads past the
 *              end of the input.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id cpp/custom/fuzzer-input-not-null-terminated
 * @tags security
 *       external/cwe/cwe-126
 *       external/cwe/cwe-170
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.models.interfaces.ArrayFunction
import semmle.code.cpp.commons.Printf
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.valuenumbering.GlobalValueNumbering

/**
 * A pointer to a fuzzer-provided test case buffer, which carries an explicit
 * length and is not null-terminated:
 * - the `data` parameter of a libFuzzer `LLVMFuzzerTestOneInput` entry point, or
 * - the AFL++ shared-memory test case buffer (`__AFL_FUZZ_TESTCASE_BUF`, which
 *   expands to `__afl_fuzz_ptr`).
 */
class FuzzerInputBuffer extends DataFlow::Node {
  FuzzerInputBuffer() {
    exists(Function f |
      f.hasGlobalName("LLVMFuzzerTestOneInput") and
      f.getNumberOfParameters() = 2 and
      this.asParameter() = f.getParameter(0)
    )
    or
    this.asExpr().(VariableAccess).getTarget().hasGlobalName("__afl_fuzz_ptr")
  }
}

/** A libFuzzer entry point: `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`. */
class FuzzerEntryPoint extends Function {
  FuzzerEntryPoint() {
    this.hasGlobalName("LLVMFuzzerTestOneInput") and
    this.getNumberOfParameters() = 2
  }

  Parameter getDataParameter() { result = this.getParameter(0) }
  Parameter getSizeParameter() { result = this.getParameter(1) }
}

/**
 * Holds if `e` is an argument that `call` reads as a null-terminated string
 * without any explicit length bound.
 */
predicate isNullTerminatedStringArgument(Call call, Expr e) {
  exists(ArrayFunction f, int i |
    f = call.getTarget() and
    f.hasArrayWithNullTerminator(i) and
    e = call.getArgument(i) and
    // Length-bounded variants such as `strnlen` and `strncmp` do not read past the bound.
    not f.getName().regexpMatch("(str|wcs|_mbs)n.*")
  )
  or
  exists(FormattingFunctionCall fc | fc = call |
    e = fc.getFormat()
    or
    exists(FormatLiteral fl, int n |
      fl = fc.getFormat() and
      e = fc.getConversionArgument(n) and
      fl.getConversionChar(n) = "s" and
      // `%.*s` stops at a nonnegative dynamic precision; `%.10s` is bounded.
      (
        not fl.hasPrecision(n) or
        hasNegativeDynamicPrecision(fl, n)
      )
    )
  )
}

/** Holds if a dynamic precision may be negative and is not a cast from an unsigned size. */
predicate hasNegativeDynamicPrecision(FormatLiteral fl, int n) {
  fl.hasImplicitPrecision(n) and
  exists(Expr precision |
    precision = fl.getUse().getPrecisionArgument(n) and
    (
      precision.getValue().toInt() < 0
      or
      precision.getType().getUnderlyingType().(IntegralType).isSigned() and
      lowerBound(precision) < 0 and
      not precision.getUnconverted().getType().getUnderlyingType().(IntegralType).isUnsigned()
    )
  )
}

module FuzzerInputNotNullTerminatedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FuzzerInputBuffer }

  predicate isSink(DataFlow::Node sink) { isNullTerminatedStringArgument(_, sink.asExpr()) }

  predicate isBarrier(DataFlow::Node node) {
    exists(
      FuzzerEntryPoint f, ArrayExpr ae, SubExpr sub, GuardCondition g, GuardCondition nonempty,
      BasicBlock bb
    |
      ae.getArrayBase().getUnconverted().(VariableAccess).getTarget() = f.getDataParameter() and
      f.getSizeParameter().getUnspecifiedType().(IntegralType).isUnsigned() and
      sub = ae.getArrayOffset() and
      sub.getLeftOperand().(VariableAccess).getTarget() = f.getSizeParameter() and
      sub.getRightOperand().getValue().toInt() = 1 and
      g.ensuresEq(ae, 0, bb, true) and
      nonempty.ensuresEq(f.getSizeParameter().getAnAccess(), 0, bb, false) and
      bb = node.asExpr().getBasicBlock() and
      globalValueNumber(node.asExpr()) = globalValueNumber(ae.getArrayBase())
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    // Pointer arithmetic into the input buffer, for example `data + 4`.
    exists(PointerAddExpr add |
      n1.asExpr() = add.getLeftOperand() and
      n2.asExpr() = add
    )
  }
}

module FuzzerInputNotNullTerminatedFlow = DataFlow::Global<FuzzerInputNotNullTerminatedConfig>;

import FuzzerInputNotNullTerminatedFlow::PathGraph

from
  FuzzerInputNotNullTerminatedFlow::PathNode source,
  FuzzerInputNotNullTerminatedFlow::PathNode sink, Call call
where
  FuzzerInputNotNullTerminatedFlow::flowPath(source, sink) and
  isNullTerminatedStringArgument(call, sink.getNode().asExpr())
select sink.getNode(), source, sink,
  "$@ is read as a null-terminated string by $@, but it is not null-terminated.", source.getNode(),
  "Fuzzer input buffer", call, call.toString()
