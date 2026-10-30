/**
 * @name Server-side template injection
 * @description Parsing user-controlled text as a `text/template` or `html/template`
 *              template lets an attacker invoke exported methods of the data passed
 *              to `Execute`, read its fields, and call template functions.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id go/template-injection
 * @tags security
 *       external/cwe/cwe-1336
 *       external/cwe/cwe-094
 */

import go

/**
 * A call to `Parse` on a `text/template` or `html/template` `Template`, whose
 * argument is the text that is compiled into a template.
 */
class TemplateParseCall extends DataFlow::MethodCallNode {
  TemplateParseCall() {
    this.getTarget().hasQualifiedName(["text/template", "html/template"], "Template", "Parse")
  }

  /** Gets the template text argument of this call. */
  DataFlow::Node getTemplateText() { result = this.getArgument(0) }
}

module TemplateInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink = any(TemplateParseCall c).getTemplateText() }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module TemplateInjectionFlow = TaintTracking::Global<TemplateInjectionConfig>;

import TemplateInjectionFlow::PathGraph

from TemplateInjectionFlow::PathNode source, TemplateInjectionFlow::PathNode sink
where TemplateInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This template text depends on a $@.", source.getNode(),
  "user-provided value"
