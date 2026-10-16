/**
 * @name Uncontrolled data used in path expression (captured variables)
 * @description Accessing paths influenced by users can allow an attacker to access
 *              unexpected resources. This query extends `py/path-injection` with
 *              flow through variables that are defined by tuple unpacking or `for`
 *              loops and then captured by a comprehension, generator expression,
 *              lambda or nested function. Only results not already reported by
 *              `py/path-injection` are reported.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @sub-severity high
 * @precision high
 * @id py/path-injection-captured-variable
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
import CapturedVariableFlow as CapturedVariableFlow

module PathInjectionCapturedVariableConfig implements DataFlow::StateConfigSig {
  class FlowState = PathInjectionConfig::FlowState;

  predicate isSource = PathInjectionConfig::isSource/2;

  predicate isSink = PathInjectionConfig::isSink/2;

  predicate isBarrier = PathInjectionConfig::isBarrier/1;

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

module PathInjectionCapturedVariableFlow =
  TaintTracking::GlobalWithState<PathInjectionCapturedVariableConfig>;

import PathInjectionCapturedVariableFlow::PathGraph

from
  PathInjectionCapturedVariableFlow::PathNode source,
  PathInjectionCapturedVariableFlow::PathNode sink
where
  PathInjectionCapturedVariableFlow::flowPath(source, sink) and
  // Avoid duplicating results that the standard `py/path-injection` query reports.
  not PathInjectionFlow::flow(source.getNode(), sink.getNode())
select sink.getNode(), source, sink, "This path depends on a $@.", source.getNode(),
  "user-provided value"
