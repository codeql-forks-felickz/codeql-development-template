/**
 * @name Code injection via fetched remote content
 * @description Fetching content from a user-controlled URL and then interpreting that
 *              content as code allows a malicious user to execute arbitrary code.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id py/custom/code-injection-remote-content
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 *       external/cwe/cwe-116
 */

import python
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.CodeInjectionQuery as Upstream

/**
 * Gets a reference to the response of an outgoing HTTP request, such as the result of
 * `urllib.request.urlopen(...)`.
 *
 * `urllib.request.Request(...)` is excluded, since it only constructs a request object.
 */
private DataFlow::TypeTrackingNode fetchedResponse(DataFlow::TypeTracker t) {
  t.start() and
  exists(Http::Client::Request req |
    req.getFramework() != "urllib.request.Request" and
    result = req
  )
  or
  exists(DataFlow::TypeTracker t2 | result = fetchedResponse(t2).track(t2, t))
}

/** Gets a reference to the response of an outgoing HTTP request. */
private DataFlow::Node fetchedResponse() {
  fetchedResponse(DataFlow::TypeTracker::end()).flowsTo(result)
}

/**
 * Holds if taint flows from `nodeFrom` to `nodeTo` because `nodeFrom` determines which remote
 * content is fetched by an outgoing HTTP request, and `nodeTo` is either that request or a
 * read of the fetched response body.
 */
private predicate fetchedContentStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
  // URL -> request/response object (also chains `urllib.request.Request(url)` into `urlopen`)
  nodeFrom = nodeTo.(Http::Client::Request).getAUrlPart()
  or
  // response object -> response body
  nodeFrom = fetchedResponse() and
  (
    nodeTo
        .(DataFlow::MethodCallNode)
        .calls(nodeFrom,
          ["read", "read1", "readline", "readlines", "json", "text", "iter_content", "iter_lines"])
    or
    nodeTo.(DataFlow::AttrRead).accesses(nodeFrom, ["text", "content", "data"])
  )
}

private module CodeInjectionRemoteContentConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Upstream::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Upstream::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Upstream::Sanitizer }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    fetchedContentStep(nodeFrom, nodeTo)
  }
}

module CodeInjectionRemoteContentFlow = TaintTracking::Global<CodeInjectionRemoteContentConfig>;

import CodeInjectionRemoteContentFlow::PathGraph

from CodeInjectionRemoteContentFlow::PathNode source, CodeInjectionRemoteContentFlow::PathNode sink
where
  CodeInjectionRemoteContentFlow::flowPath(source, sink) and
  // Only report flows that the standard `py/code-injection` query does not already report.
  not Upstream::CodeInjectionFlow::flow(source.getNode(), sink.getNode())
select sink.getNode(), source, sink,
  "This code execution depends on remote content fetched from a URL controlled by a $@.",
  source.getNode(), "user-provided value"
