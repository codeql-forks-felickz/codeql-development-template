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
      // `%.*s` and `%.10s` stop reading at the given precision.
      not fl.hasPrecision(n)
    )
  )
}

module FuzzerInputNotNullTerminatedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FuzzerInputBuffer }

  predicate isSink(DataFlow::Node sink) { isNullTerminatedStringArgument(_, sink.asExpr()) }

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
