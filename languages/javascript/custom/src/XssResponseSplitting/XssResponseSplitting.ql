/**
 * @name Stored cross-site scripting through Angular sanitizer bypass of HTTP response data
 * @description Passing data received in an HTTP response to an Angular
 *              `DomSanitizer.bypassSecurityTrust*` method disables Angular's
 *              built-in sanitization of `[innerHTML]` and `[style]` template
 *              bindings, allowing stored cross-site scripting.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision medium
 * @id js/xss-response-splitting
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript
private import semmle.javascript.security.dataflow.DomBasedXssCustomizations

/**
 * Gets a call `inject(token)` to the Angular `inject` function, where `token`
 * is the local source of the first argument.
 */
private DataFlow::CallNode angularInjectCall(DataFlow::SourceNode token) {
  result = DataFlow::moduleMember("@angular/core", "inject").getACall() and
  token = result.getArgument(0).getALocalSource()
}

/**
 * Gets a reference to the service `name` from module `mod`, obtained through
 * the Angular `inject()` function (for example `inject(DomSanitizer)`).
 */
private DataFlow::SourceNode injectedService(string mod, string name, DataFlow::TypeTracker t) {
  t.start() and
  result = angularInjectCall(DataFlow::moduleMember(mod, name))
  or
  exists(DataFlow::TypeTracker t2 | result = injectedService(mod, name, t2).track(t2, t))
}

private DataFlow::SourceNode injectedService(string mod, string name) {
  result = injectedService(mod, name, DataFlow::TypeTracker::end())
}

/**
 * Gets a reference to an instance of the application class `cls`, obtained
 * through the Angular `inject()` function (for example `inject(ProductService)`).
 */
private DataFlow::SourceNode injectedClassInstance(DataFlow::ClassNode cls, DataFlow::TypeTracker t) {
  t.start() and
  result = angularInjectCall(cls.getAClassReference())
  or
  exists(DataFlow::TypeTracker t2 | result = injectedClassInstance(cls, t2).track(t2, t))
}

private DataFlow::SourceNode injectedClassInstance(DataFlow::ClassNode cls) {
  result = injectedClassInstance(cls, DataFlow::TypeTracker::end())
}

/** Gets a reference to an Angular `DomSanitizer`. */
private DataFlow::SourceNode domSanitizer() {
  result = Angular2::domSanitizer()
  or
  result = injectedService(["@angular/platform-browser", "@angular/core"], "DomSanitizer")
}

/** Gets a reference to an Angular `HttpClient`. */
private DataFlow::SourceNode httpClient() {
  result = Angular2::httpClient()
  or
  result = injectedService("@angular/common/http", "HttpClient")
}

/** Data received in the response to an HTTP request made by the client. */
private class HttpResponseData extends DataFlow::Node {
  HttpResponseData() {
    this = any(ClientRequest r).getAResponseDataNode()
    or
    // `HttpClient` request methods return an observable of the response.
    this =
      httpClient()
          .getAMethodCall([
              "get", "post", "put", "patch", "delete", "head", "options", "jsonp", "request"
            ])
  }
}

/**
 * A value passed to `DomSanitizer.bypassSecurityTrustHtml` or
 * `DomSanitizer.bypassSecurityTrustStyle`, which marks it as safe to render in
 * an `[innerHTML]` or `[style]` template binding without sanitization.
 */
private class SanitizerBypassSink extends DataFlow::Node {
  SanitizerBypassSink() {
    this =
      domSanitizer()
          .getAMethodCall(["bypassSecurityTrustHtml", "bypassSecurityTrustStyle"])
          .getArgument(0)
  }
}

/**
 * Holds if `pred -> succ` is a step from a value returned by a method of a
 * service class, to a call of that method on an instance obtained through
 * `inject(Service)`.
 */
private predicate injectedServiceReturnStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(DataFlow::ClassNode cls, string name |
    pred = cls.getInstanceMethod(name).getAReturn() and
    succ = injectedClassInstance(cls).getAMethodCall(name)
  )
}

/**
 * A value-preserving step through RxJS constructs that are not modeled by the
 * standard library. Preserving the value (rather than adding a taint step)
 * keeps track of which element of a combined observable holds which input.
 */
private class RxJsCombineFlowStep extends DataFlow::AdditionalFlowStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    // `forkJoin([a$, b$])`, `combineLatest({ a: a$ })` or `zip(a$, b$)`
    exists(DataFlow::CallNode call |
      call = DataFlow::moduleMember("rxjs", ["forkJoin", "combineLatest", "zip"]).getACall() and
      pred = call.getAnArgument() and
      succ = call
    )
  }

  override predicate jumpStep(DataFlow::Node pred, DataFlow::Node succ) {
    // `obs$.subscribe((value) => ...)` or `obs$.subscribe({ next: (value) => ... })`
    exists(DataFlow::MethodCallNode call, DataFlow::FunctionNode callback |
      call.getMethodName() = "subscribe" and
      pred = call.getReceiver() and
      succ = callback.getParameter(0)
    |
      callback = call.getCallback(0)
      or
      callback =
        call.getArgument(0)
            .getALocalSource()
            .(DataFlow::ObjectLiteralNode)
            .getAPropertySource("next")
    )
  }
}

module XssResponseSplittingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof HttpResponseData }

  predicate isSink(DataFlow::Node sink) { sink instanceof SanitizerBypassSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof DomBasedXss::Sanitizer }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    injectedServiceReturnStep(pred, succ)
  }
}

module XssResponseSplittingFlow = TaintTracking::Global<XssResponseSplittingConfig>;

import XssResponseSplittingFlow::PathGraph

from XssResponseSplittingFlow::PathNode source, XssResponseSplittingFlow::PathNode sink
where XssResponseSplittingFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Angular sanitization is bypassed for a value that depends on $@, allowing stored cross-site scripting when it is rendered.",
  source.getNode(), "HTTP response data"
