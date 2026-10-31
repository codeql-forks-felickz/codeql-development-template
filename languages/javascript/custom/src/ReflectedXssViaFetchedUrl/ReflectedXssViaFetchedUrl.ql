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
import semmle.javascript.security.dataflow.UrlConcatenation
private import semmle.javascript.security.dataflow.Xss::Shared as SharedXss

/** Gets the URL argument of `request`. */
private DataFlow::Node getRequestUrl(ClientRequest request) {
  if request = DataFlow::moduleMember("needle", "request").getACall()
  then
    // `needle.request(method, url, data, [options], callback)`: the library model reports the
    // method as the URL.
    result = request.(DataFlow::CallNode).getArgument(1)
  else result = request.getUrl()
}

private predicate isUrlOriginOrHost(DataFlow::Node property, DataFlow::Node url) {
  exists(DataFlow::PropRead read, DataFlow::NewNode parsedUrl |
    read = property and
    read.getPropertyName() = ["origin", "host", "hostname"] and
    parsedUrl = read.getBase().getALocalSource() and
    parsedUrl.getCalleeNode() = DataFlow::globalVarRef("URL") and
    url = parsedUrl.getArgument(0)
  )
}

private predicate isUrlOriginOrHostEquality(EqualityTest test, DataFlow::Node url) {
  exists(DataFlow::Node property, Expr constant |
    test.hasOperands(property.asExpr(), constant) and
    exists(constant.getStringValue()) and
    isUrlOriginOrHost(property, url)
  )
}

private class UrlOriginOrHostEqualityGuard extends DataFlow::ValueNode {
  override EqualityTest astNode;

  UrlOriginOrHostEqualityGuard() { isUrlOriginOrHostEquality(astNode, _) }

  predicate blocksExpr(boolean outcome, Expr e, TFlowState state) {
    state = TUrl() and
    outcome = astNode.getPolarity() and
    isUrlOriginOrHostEquality(astNode, e.flow())
  }
}

private class UrlOriginOrHostAllowListGuard extends InclusionTest {
  predicate blocksExpr(boolean outcome, Expr e, TFlowState state) {
    state = TUrl() and
    outcome = this.getPolarity() and
    isUrlOriginOrHost(this.getContainedNode(), e.flow()) and
    exists(DataFlow::ArrayCreationNode allowList |
      this.getContainerNode().getALocalSource() = allowList and
      allowList.getAnElement().getStringValue() != "" and
      not exists(DataFlow::Node element |
        element = allowList.getAnElement() and
        not exists(element.getStringValue())
      )
    )
  }
}

/**
 * Holds if `read` reads response metadata, such as the status code, which the remote
 * server cannot use to inject HTML.
 */
predicate isResponseMetadataRead(DataFlow::PropRead read) {
  read.getPropertyName() = ["statusCode", "status", "ok", "redirected"] and
  exists(ClientRequest request | read.getBase().getALocalSource() = request.getAResponseDataNode())
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
    or
    state = TUrl() and
    (
      node = HostnameSanitizerGuard::getABarrierNode() or
      node =
        DataFlow::MakeStateBarrierGuard<TFlowState, UrlOriginOrHostEqualityGuard>::getABarrierNode(state) or
      node =
        DataFlow::MakeStateBarrierGuard<TFlowState, UrlOriginOrHostAllowListGuard>::getABarrierNode(state)
    )
  }

  predicate isBarrierOut(DataFlow::Node node, FlowState state) {
    state = TUrl() and hostnameSanitizingPrefixEdge(node, _)
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    // If the user controls the scheme and host of a fetched URL, they control the response.
    exists(ClientRequest request |
      node1 = getRequestUrl(request) and
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
