/**
 * @name Reflected cross-site scripting via attacker-chosen URL
 * @description Fetching a URL whose origin is controlled by the user and writing the
 *              response directly to an HTTP response allows the user to serve arbitrary
 *              HTML and script from the application's origin.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id js/reflected-xss-via-fetched-url
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 *       external/cwe/cwe-918
 */

import javascript
import semmle.javascript.security.dataflow.ReflectedXssCustomizations
private import semmle.javascript.security.dataflow.Xss::Shared as SharedXss

/**
 * Gets the leftmost fragment of the URL `url`, that is, the part of the URL that
 * determines its scheme and host.
 */
DataFlow::Node urlPrefix(DataFlow::Node url) {
  exists(StringOps::ConcatenationRoot root | DataFlow::localFlowStep*(root, url) |
    result = root.getFirstLeaf()
  )
  or
  not exists(StringOps::ConcatenationRoot root | DataFlow::localFlowStep*(root, url)) and
  result = url
}

/**
 * Holds if `request` fetches a URL whose leftmost fragment is `prefix`.
 */
predicate fetchesUrlWithPrefix(ClientRequest request, DataFlow::Node prefix) {
  exists(DataFlow::Node url |
    if request = DataFlow::moduleMember("needle", "request").getACall()
    then
      // `needle.request(method, url, data, [options], callback)`: the library model reports the
      // method as the URL.
      url = request.(DataFlow::CallNode).getArgument(1)
    else url = request.getUrl()
  |
    prefix = urlPrefix(url)
  )
}

/**
 * Holds if `read` reads response metadata, such as the status code, which the remote
 * server cannot use to inject HTML.
 */
predicate isResponseMetadataRead(DataFlow::PropRead read) {
  read.getPropertyName() =
    ["statusCode", "status", "statusMessage", "statusText", "ok", "headers", "redirected"]
}

/** The two phases of the flow: the request URL, and the fetched response. */
newtype TFlowState =
  TUrl() or
  TResponse()

module ReflectedXssViaFetchedUrlConfig implements DataFlow::StateConfigSig {
  class FlowState = TFlowState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    source instanceof ReflectedXss::Source and state = TUrl()
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    sink instanceof ReflectedXss::Sink and state = TResponse()
  }

  predicate isBarrier(DataFlow::Node node, FlowState state) {
    state = TResponse() and
    (
      isResponseMetadataRead(node) or
      node instanceof ReflectedXss::Sanitizer or
      node = SharedXss::BarrierGuard::getABarrierNode()
    )
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    // If the user controls the scheme and host of a fetched URL, they control the response.
    exists(ClientRequest request |
      fetchesUrlWithPrefix(request, node1) and
      node2 = request.getAResponseDataNode(_, _) and
      state1 = TUrl() and
      state2 = TResponse()
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module ReflectedXssViaFetchedUrlFlow =
  TaintTracking::GlobalWithState<ReflectedXssViaFetchedUrlConfig>;

import ReflectedXssViaFetchedUrlFlow::PathGraph

from ReflectedXssViaFetchedUrlFlow::PathNode source, ReflectedXssViaFetchedUrlFlow::PathNode sink
where ReflectedXssViaFetchedUrlFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Cross-site scripting vulnerability due to the response of a request to a $@.", source.getNode(),
  "user-controlled URL"
