/**
 * @name AngularJS client-side template injection
 * @description Writing user-controlled text into a page that is bootstrapped by AngularJS
 *              (`ng-app`) lets an attacker inject AngularJS expressions that are compiled
 *              and evaluated, even when the text is HTML-encoded.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision medium
 * @id js/angularjs-client-side-template-injection
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-094
 *       external/cwe/cwe-1336
 */

import javascript

/**
 * Holds if `attr` marks its element as the root of an AngularJS application
 * (`ng-app` and its normalized aliases such as `data-ng-app`).
 */
predicate isNgAppAttribute(HTML::Attribute attr) {
  attr.getName().regexpMatch("(?i)((data|x)[-:_])?ng[-:_]app")
}

/**
 * Holds if `file` is an HTML page containing an AngularJS application root
 * whose content is not wholly marked `ng-non-bindable`.
 */
predicate isAngularJSPage(HTML::HtmlFile file) {
  exists(HTML::Element root |
    isNgAppAttribute(root.getAnAttribute()) and
    root.getFile() = file and
    not exists(root.getParent*().getAttributeByName("ng-non-bindable"))
  )
}

/** Holds if `tl` is a script that runs in an AngularJS page. */
predicate runsInAngularJSPage(TopLevel tl) {
  exists(HTML::ScriptElement script |
    tl = script.getScript() and
    isAngularJSPage(script.getFile())
  )
}

/**
 * A value written into the DOM as plain text. Such writes are HTML-encoded and thus not
 * XSS sinks, but AngularJS still compiles any `{{ }}` expressions they contain.
 */
class DomTextSink extends DataFlow::Node {
  DomTextSink() {
    exists(JQuery::MethodCall call |
      call.getMethodName() = "text" and
      this = call.getArgument(0)
    )
    or
    exists(DataFlow::PropWrite pw |
      pw.getPropertyName() = ["textContent", "innerText"] and
      this = pw.getRhs()
    )
    or
    this = DataFlow::globalVarRef("document").getAMethodCall("createTextNode").getArgument(0)
  }
}

module AngularJSTemplateInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof DomTextSink and
    runsInAngularJSPage(sink.getTopLevel())
  }

  predicate isBarrier(DataFlow::Node node) {
    // A replacement that removes or encodes curly braces neutralizes AngularJS interpolation.
    exists(StringReplaceCall replace, RegExpConstant c |
      node = replace and
      replace.isGlobal() and
      c.getRootTerm() = replace.getRegExp().getRoot() and
      c.getValue().regexpMatch(".*[{}].*") and
      not replace.getRawReplacement().getStringValue().regexpMatch(".*[{}].*")
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // A common query-string parsing idiom: the replacement callback of
    // `location.search.replace(re, function(match, key, value) { ... })`
    // receives substrings of the tainted receiver as its parameters.
    exists(StringReplaceCall replace |
      pred = replace.getReceiver() and
      succ = replace.getReplacementCallback().getAParameter()
    )
    or
    // ... whose results are typically stored with a computed key, `params[key] = value`,
    // and later read back with a constant key, `params['user']`.
    exists(Variable v, DataFlow::PropWrite pw, DataFlow::PropRead pr |
      not exists(pw.getPropertyName()) and
      pw.getBase().asExpr() = v.getAnAccess() and
      pr.getBase().asExpr() = v.getAnAccess() and
      pred = pw.getRhs() and
      succ = pr
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module AngularJSTemplateInjectionFlow = TaintTracking::Global<AngularJSTemplateInjectionConfig>;

import AngularJSTemplateInjectionFlow::PathGraph

from AngularJSTemplateInjectionFlow::PathNode source, AngularJSTemplateInjectionFlow::PathNode sink
where AngularJSTemplateInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This text is written into an AngularJS application page and may be compiled as a template, as it depends on a $@.",
  source.getNode(), "user-provided value"
