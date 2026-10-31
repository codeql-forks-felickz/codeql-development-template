/**
 * @name Cross-site scripting through Swig templates with autoescaping disabled
 * @description User-controlled data reaches Swig template output when global autoescaping is disabled.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision medium
 * @id js/xss-swig-autoescape-disabled
 * @tags security
 *       external/cwe/cwe-079
 */

import javascript
private import semmle.javascript.Concepts
private import semmle.javascript.frameworks.Templating
private import semmle.javascript.security.dataflow.DomBasedXssCustomizations

/**
 * Holds if Swig autoescaping is disabled through `swig.setDefaults`.
 */
private predicate swigAutoescapeDisabled() {
  exists(DataFlow::CallNode call, DataFlow::ObjectLiteralNode options, DataFlow::Node value |
    call = DataFlow::moduleMember("swig", "setDefaults").getACall() and
    options = call.getArgument(0).getALocalSource() and
    options.hasPropertyWrite("autoescape", value) and
    value.mayHaveBooleanValue(false)
  )
}

private class UnescapedTemplateOutput extends DataFlow::Node {
  UnescapedTemplateOutput() {
    exists(Templating::TemplatePlaceholderTag tag |
      tag.isEscapingInterpolation() and
      Templating::getLikelyTemplateSyntax(tag.getFile()).getAPackageName() = "swig" and
      swigAutoescapeDisabled() and
      this = tag.asDataFlowNode()
    )
  }
}

module XssUnescapedTemplateOutputConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
    or
    exists(DatabaseAccess access | source = access.getAResult())
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof UnescapedTemplateOutput }

  predicate isBarrier(DataFlow::Node node) { node instanceof DomBasedXss::Sanitizer }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { none() }
}

module XssUnescapedTemplateOutputFlow = TaintTracking::Global<XssUnescapedTemplateOutputConfig>;

import XssUnescapedTemplateOutputFlow::PathGraph

from XssUnescapedTemplateOutputFlow::PathNode source, XssUnescapedTemplateOutputFlow::PathNode sink
where XssUnescapedTemplateOutputFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Unescaped template output depends on $@.", source.getNode(),
  "user-controlled data"
