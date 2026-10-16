/**
 * @name Uncontrolled data used in path expression (extended coverage)
 * @description Accessing paths influenced by users can allow an attacker to access
 *              unexpected resources. This query extends `py/path-injection` with
 *              flow through variables that are defined by tuple unpacking or `for`
 *              loops and then captured by a comprehension, generator expression,
 *              lambda or nested function, and with file paths passed to operating
 *              system file commands such as `mv` or `cp`. Only results not already
 *              reported by `py/path-injection` are reported.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @sub-severity high
 * @precision high
 * @id py/path-injection-extended
 * @tags correctness
 *       security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 *       external/cwe/cwe-099
 */

import python
import semmle.python.security.dataflow.PathInjectionQuery
import semmle.python.ApiGraphs
import CapturedVariableFlow as CapturedVariableFlow
import ShellFileCommandSinks as ShellFileCommandSinks

module PathInjectionExtendedConfig implements DataFlow::StateConfigSig {
  class FlowState = PathInjectionConfig::FlowState;

  predicate isSource = PathInjectionConfig::isSource/2;

  predicate isSink(DataFlow::Node sink, FlowState state) {
    PathInjectionConfig::isSink(sink, state)
    or
    ShellFileCommandSinks::isShellFileCommandPathSink(sink) and
    (
      state instanceof NotNormalized or
      state instanceof NormalizedUnchecked
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    PathInjectionConfig::isBarrier(node)
    or
    // `os.path.basename` strips any directory components, including `../`.
    node = API::moduleImport("os").getMember("path").getMember("basename").getACall()
  }

  predicate isBarrier = PathInjectionConfig::isBarrier/2;

  predicate isAdditionalFlowStep(
    DataFlow::Node nodeFrom, FlowState stateFrom, DataFlow::Node nodeTo, FlowState stateTo
  ) {
    PathInjectionConfig::isAdditionalFlowStep(nodeFrom, stateFrom, nodeTo, stateTo)
    or
    CapturedVariableFlow::step(nodeFrom, nodeTo) and
    stateFrom = stateTo
  }
}

module PathInjectionExtendedFlow = TaintTracking::GlobalWithState<PathInjectionExtendedConfig>;

import PathInjectionExtendedFlow::PathGraph

from PathInjectionExtendedFlow::PathNode source, PathInjectionExtendedFlow::PathNode sink
where
  PathInjectionExtendedFlow::flowPath(source, sink) and
  // Avoid duplicating results that the standard `py/path-injection` query reports.
  not PathInjectionFlow::flow(source.getNode(), sink.getNode())
select sink.getNode(), source, sink, "This path depends on a $@.", source.getNode(),
  "user-provided value"
