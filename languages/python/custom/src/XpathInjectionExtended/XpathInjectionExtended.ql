/**
 * @name XPath query built from user-controlled sources (extended)
 * @description Building a XPath query from user-controlled sources is vulnerable to insertion of
 *              malicious Xpath code by the user. This variant of `py/xpath-injection` also
 *              tracks user-controlled values through variables that are defined by iterable
 *              unpacking and read in a nested scope, such as a generator expression.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/xpath-injection-extended
 * @tags security
 *       external/cwe/cwe-643
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.XpathInjectionCustomizations
import Shared.CapturedUnpackedVariableFlow

private module XpathInjectionExtendedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof XpathInjection::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof XpathInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof XpathInjection::Sanitizer }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    capturedUnpackedVariableStep(nodeFrom, nodeTo)
  }
}

module XpathInjectionExtendedFlow = TaintTracking::Global<XpathInjectionExtendedConfig>;

import XpathInjectionExtendedFlow::PathGraph

from XpathInjectionExtendedFlow::PathNode source, XpathInjectionExtendedFlow::PathNode sink
where XpathInjectionExtendedFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "XPath expression depends on a $@.", source.getNode(),
  "user-provided value"
