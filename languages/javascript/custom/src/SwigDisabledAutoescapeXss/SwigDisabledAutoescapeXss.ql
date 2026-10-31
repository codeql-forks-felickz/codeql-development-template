/**
 * @name Cross-site scripting through Swig templates with autoescape disabled
 * @description Rendering untrusted request data in a Swig template while autoescaping is disabled
 *              inserts it into the response as raw HTML, allowing cross-site scripting.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id js/swig-disabled-autoescape-xss
 * @tags security
 *       frameworks/swig
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript
import semmle.javascript.security.dataflow.ReflectedXssCustomizations
import SwigDisabledAutoescapeXssFlow::PathGraph

/** Holds if Swig's global autoescape setting is explicitly disabled. */
predicate swigAutoescapeDisabled() {
  exists(DataFlow::CallNode setDefaults, DataFlow::ObjectLiteralNode options |
    setDefaults = DataFlow::moduleMember("swig", "setDefaults").getACall() and
    options = setDefaults.getArgument(0).getALocalSource() and
    options.getAPropertyWrite("autoescape").getRhs().mayHaveBooleanValue(false)
  )
}

/** Swig interpolation syntax, where double braces are raw if autoescaping is disabled. */
class SwigDisabledAutoescapeSyntax extends Templating::TemplateSyntax {
  SwigDisabledAutoescapeSyntax() { this = "swig-with-autoescape-disabled" }

  override string getRawInterpolationRegexp() { result = "(?s)\\{\\{(.*?)\\}\\}" }

  override string getEscapingInterpolationRegexp() { none() }

  override string getAFileExtension() { result = "html" }

  override string getAPackageName() { result = "swig" }
}

/** An Express response rendered through Swig. */
class SwigTemplateInstantiation extends Templating::TemplateInstantiation::Range,
  DataFlow::CallNode
{
  SwigTemplateInstantiation() {
    exists(Express::ResponseSource res |
      this = res.ref().getAMethodCall("render")
    )
  }

  override DataFlow::SourceNode getOutput() { result = this }

  override DataFlow::Node getTemplateFileNode() { result = this.getArgument(0) }

  override DataFlow::Node getTemplateParamsNode() { result = this.getArgument(1) }

  override Templating::TemplateSyntax getTemplateSyntax() {
    result instanceof SwigDisabledAutoescapeSyntax
  }
}

module SwigDisabledAutoescapeXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ReflectedXss::Source }

  predicate isSink(DataFlow::Node sink) {
    swigAutoescapeDisabled() and
    exists(Templating::TemplatePlaceholderTag tag, SwigTemplateInstantiation inst |
      tag.isRawInterpolation() and
      sink = tag.asDataFlowNode() and
      tag.getFile() = inst.(Templating::TemplateInstantiation).getTemplateFile()
    )
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof ReflectedXss::Sanitizer }
}

module SwigDisabledAutoescapeXssFlow = TaintTracking::Global<SwigDisabledAutoescapeXssConfig>;

from SwigDisabledAutoescapeXssFlow::PathNode source, SwigDisabledAutoescapeXssFlow::PathNode sink
where SwigDisabledAutoescapeXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Cross-site scripting vulnerability: $@ is rendered without escaping by a Swig template.",
  source.getNode(), "this value"
