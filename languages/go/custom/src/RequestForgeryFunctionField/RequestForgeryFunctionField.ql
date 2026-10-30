/**
 * @name Uncontrolled data used in network request via function-valued field
 * @description Sending network requests with user-controlled data allows for request
 *              forgery attacks. This variant of `go/request-forgery` also follows
 *              calls made through function-valued struct fields.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id go/request-forgery-function-field
 * @tags security
 *       external/cwe/cwe-918
 */

import go
import semmle.go.security.RequestForgery
import semmle.go.security.SafeUrlFlow
import FunctionFieldDispatch

module SafeUrlFunctionFieldConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof SafeUrlFlow::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof SafeUrlFlow::Sink }

  predicate isBarrierOut(DataFlow::Node node) {
    exists(Write w, Field f | f.hasQualifiedName("net/url", "URL", "Host") |
      w.writesFieldPreUpdate(node, f, _)
    )
    or
    node instanceof SafeUrlFlow::SanitizerEdge
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Write w, Field f | f.hasQualifiedName("net/url", "URL", "Host") |
      w.writesField(succ, f, pred)
    )
    or
    functionFieldDispatchStep(pred, succ)
  }

  predicate observeDiffInformedIncrementalMode() { none() }
}

module SafeUrlFunctionFieldFlow = TaintTracking::Global<SafeUrlFunctionFieldConfig>;

module RequestForgeryFunctionFieldConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RequestForgery::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof RequestForgery::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof RequestForgery::Sanitizer }

  predicate isBarrierOut(DataFlow::Node node) { node instanceof RequestForgery::SanitizerEdge }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // propagate to a URL when its host is assigned to (as in `go/request-forgery`)
    exists(Write w, Field f | f.hasQualifiedName("net/url", "URL", "Host") |
      w.writesField(succ, f, pred)
    )
    or
    functionFieldDispatchStep(pred, succ)
  }

  predicate observeDiffInformedIncrementalMode() { any() }

  Location getASelectedSinkLocation(DataFlow::Node sink) {
    result = sink.getLocation()
    or
    result = sink.(RequestForgery::Sink).getARequest().getLocation()
  }
}

module RequestForgeryFunctionFieldFlow = TaintTracking::Global<RequestForgeryFunctionFieldConfig>;

import RequestForgeryFunctionFieldFlow::PathGraph

from
  RequestForgeryFunctionFieldFlow::PathNode source, RequestForgeryFunctionFieldFlow::PathNode sink,
  DataFlow::Node request
where
  RequestForgeryFunctionFieldFlow::flowPath(source, sink) and
  request = sink.getNode().(RequestForgery::Sink).getARequest() and
  // this excludes flow from safe parts of request URLs, for example the full URL
  not SafeUrlFunctionFieldFlow::flow(source.getNode(), sink.getNode()) and
  // avoid duplicating alerts already reported by `go/request-forgery`
  not RequestForgery::Flow::flowTo(sink.getNode())
select request, source, sink, "The $@ of this request depends on a $@.", sink.getNode(),
  sink.getNode().(RequestForgery::Sink).getKind(), source, "user-provided value"
