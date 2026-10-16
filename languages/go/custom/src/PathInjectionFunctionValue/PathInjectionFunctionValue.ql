/**
 * @name Uncontrolled data used in path expression (including calls through function-valued fields)
 * @description Accessing paths influenced by users can allow an attacker to access unexpected
 *              resources. This variant of `go/path-injection` also follows user input into
 *              functions that are called through function values stored in struct fields.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id go/path-injection-function-value
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 *       external/cwe/cwe-099
 */

import go
import semmle.go.security.TaintedPathCustomizations
import lib.FieldFunctionValueCalls

module PathInjectionFunctionValueConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof TaintedPath::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof TaintedPath::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof TaintedPath::Sanitizer }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    fieldFunctionValueArgumentStep(pred, succ)
  }
}

module PathInjectionFunctionValueFlow = TaintTracking::Global<PathInjectionFunctionValueConfig>;

import PathInjectionFunctionValueFlow::PathGraph

from PathInjectionFunctionValueFlow::PathNode source, PathInjectionFunctionValueFlow::PathNode sink
where PathInjectionFunctionValueFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This path depends on a $@.", source.getNode(),
  "user-provided value"
