/**
 * @name Client-side cross-site scripting through ng-bind-html with SCE disabled
 * @description Binding untrusted data with `ng-bind-html` in an AngularJS application that
 *              disables strict contextual escaping (SCE) inserts the data into the DOM as
 *              raw HTML, allowing cross-site scripting.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id js/angular/sce-disabled-xss
 * @tags security
 *       frameworks/angularjs
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript
import semmle.javascript.security.dataflow.DomBasedXssCustomizations
import AngularSceDisabledXssFlow::PathGraph

/** Holds if strict contextual escaping is disabled with `$sceProvider.enabled(false)`. */
predicate sceDisabled() {
  exists(AngularJS::BuiltinServiceReference service, DataFlow::MethodCallNode mce |
    service.getName() = "$sceProvider" and
    mce = service.getAMethodCall("enabled") and
    mce.getArgument(0).mayHaveBooleanValue(false)
  )
}

/** Gets a request made with the AngularJS `$http` service. */
DataFlow::CallNode angularHttpRequest() {
  exists(AngularJS::BuiltinServiceReference http | http.getName() = "$http" |
    result = http.getACall()
    or
    result = http.getAMethodCall(["get", "head", "post", "put", "delete", "jsonp", "patch"])
  )
}

/**
 * The data of a response to an AngularJS `$http` request, for example
 * `response.data` in `$http.get(url).then(function (response) { ... })`.
 *
 * With SCE disabled, the AngularJS application trusts this data as HTML. Responses
 * frequently contain user-controlled content, either stored or reflected from
 * the request (such as an error message that echoes a search term).
 */
class AngularHttpResponseData extends DataFlow::Node {
  AngularHttpResponseData() {
    exists(DataFlow::CallNode request | request = angularHttpRequest() |
      exists(int i | i = [0, 1] |
        this =
          request.getAMethodCall("then").getABoundCallbackParameter(i, 0).getAPropertyRead("data")
      )
      or
      this =
        request.getAMethodCall("catch").getABoundCallbackParameter(0, 0).getAPropertyRead("data")
      or
      // Legacy `HttpPromise` callbacks (removed in AngularJS 1.6).
      this = request.getAMethodCall(["success", "error"]).getABoundCallbackParameter(0, 0)
    )
  }
}

/**
 * Holds if `elem` has an `ng-bind-html` directive whose expression is the plain scope
 * property `prop`.
 */
predicate ngBindHtmlProperty(DOM::ElementDefinition elem, string prop) {
  exists(AngularJS::DirectiveInstance directive, AngularJS::DirectiveTarget target |
    directive.getName() = "ngBindHtml" and
    target = directive.getATarget() and
    elem = target.getElement() and
    prop =
      target
          .(DOM::AttributeDefinition)
          .getStringValue()
          .regexpCapture("\\s*([A-Za-z_$][A-Za-z0-9_$]*)\\s*", 1)
  )
}

/**
 * The right-hand side of a write to a scope property that is rendered as raw HTML
 * with `ng-bind-html`, such as `$scope.x = value` for `<b ng-bind-html="x">`.
 */
class NgBindHtmlScopePropertyWrite extends DataFlow::Node {
  NgBindHtmlScopePropertyWrite() {
    exists(DOM::ElementDefinition elem, string prop, AngularJS::AngularScope scope |
      ngBindHtmlProperty(elem, prop) and
      scope.mayApplyTo(elem) and
      this = scope.getAnAccess().(DataFlow::SourceNode).getAPropertyWrite(prop).getRhs()
    )
  }
}

module AngularSceDisabledXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof DomBasedXss::Source
    or
    source instanceof AngularHttpResponseData
  }

  predicate isSink(DataFlow::Node sink) {
    sceDisabled() and
    sink instanceof NgBindHtmlScopePropertyWrite
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof DomBasedXss::Sanitizer
    or
    node = any(AngularJS::BuiltinServiceReference s | s.getName() = "$sanitize").getACall()
  }
}

module AngularSceDisabledXssFlow = TaintTracking::Global<AngularSceDisabledXssConfig>;

from AngularSceDisabledXssFlow::PathNode source, AngularSceDisabledXssFlow::PathNode sink
where AngularSceDisabledXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Cross-site scripting vulnerability: $@ is rendered as HTML by ng-bind-html while strict contextual escaping is disabled.",
  source.getNode(), "this value"
