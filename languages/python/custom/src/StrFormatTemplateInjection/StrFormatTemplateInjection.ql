/**
 * @name Format string built from user-controlled sources
 * @description Using a user-controlled string as the format string of `str.format`,
 *              `str.format_map` or `string.Formatter` lets the user traverse the
 *              attributes and items of the format arguments (for example
 *              `{0.__init__.__globals__}` or `{1.environ}`), which can disclose secrets
 *              and internal objects.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.5
 * @precision medium
 * @id py/str-format-template-injection
 * @tags security
 *       external/cwe/cwe-1336
 *       external/cwe/cwe-134
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.BarrierGuards
import Shared.CapturedUnpackedVariableFlow

/**
 * Holds if `arg` is a literal that offers nothing to traverse, such as `1`, `"x"`, `()` or
 * `{"name": "x"}`.
 */
private predicate isLiteralArgument(Expr arg) {
  arg instanceof StringLiteral
  or
  arg instanceof Num
  or
  arg instanceof None
  or
  arg instanceof True
  or
  arg instanceof False
  or
  (arg instanceof Tuple or arg instanceof List or arg instanceof Set) and
  forall(Expr elt | elt = arg.getASubExpression() | isLiteralArgument(elt))
  or
  isLiteralArgument(arg.(Starred).getValue())
  or
  arg instanceof Dict and
  forall(Expr e | e = arg.(Dict).getAKey() or e = arg.(Dict).getAValue() | isLiteralArgument(e))
}

/**
 * Holds if `call` passes at least one non-literal value to be formatted, ignoring the
 * first `skip` positional arguments.
 */
bindingset[skip]
private predicate hasNonLiteralFormatArgument(DataFlow::CallCfgNode call, int skip) {
  exists(Expr arg |
    exists(int i | i >= skip and arg = call.getNode().getNode().(Call).getPositionalArg(i))
    or
    arg = call.getNode().getNode().(Call).getANamedArg().(Keyword).getValue()
    or
    arg = call.getNode().getNode().(Call).getANamedArg().(DictUnpacking).getValue()
    or
    arg = call.getNode().getNode().(Call).getStarArg()
    or
    arg = call.getNode().getNode().(Call).getKwargs()
  |
    not isLiteralArgument(arg)
  )
}

/**
 * A format string whose replacement fields are resolved against non-literal arguments.
 */
private class FormatStringSink extends DataFlow::Node {
  FormatStringSink() {
    // `fmt.format(...)` and `fmt.format_map(...)`
    exists(DataFlow::MethodCallNode call |
      call.calls(this, ["format", "format_map"]) and
      not this.asExpr() instanceof StringLiteral and
      hasNonLiteralFormatArgument(call, 0)
    )
    or
    // `string.Formatter().format(fmt, ...)` and `string.Formatter().vformat(fmt, args, kwargs)`
    exists(DataFlow::CallCfgNode call |
      call =
        API::moduleImport("string")
            .getMember("Formatter")
            .getASubclass*()
            .getReturn()
            .getMember(["format", "vformat"])
            .getACall() and
      this = call.getArg(0) and
      hasNonLiteralFormatArgument(call, 1)
    )
  }
}

private module StrFormatTemplateInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof FormatStringSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof ConstCompareBarrier }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    capturedUnpackedVariableStep(nodeFrom, nodeTo)
  }
}

module StrFormatTemplateInjectionFlow = TaintTracking::Global<StrFormatTemplateInjectionConfig>;

import StrFormatTemplateInjectionFlow::PathGraph

from StrFormatTemplateInjectionFlow::PathNode source, StrFormatTemplateInjectionFlow::PathNode sink
where StrFormatTemplateInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This format string depends on a $@.", source.getNode(),
  "user-provided value"
