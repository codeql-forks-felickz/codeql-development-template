/**
 * @name HTTP header splitting in outgoing request
 * @description Writing user input directly to a header of an outgoing HTTP client
 *              request allows an attacker to inject additional headers or split the
 *              request sent to the downstream server.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id java/xss-response-splitting
 * @tags security
 *       external/cwe/cwe-113
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.ResponseSplittingQuery

/**
 * A method that adds or sets a header on an outgoing Apache HttpClient request
 * (HttpCore/HttpClient 4.x and 5.x).
 */
class ApacheHttpClientSetHeaderMethod extends Method {
  ApacheHttpClientSetHeaderMethod() {
    this.hasName(["addHeader", "setHeader"]) and
    this.getNumberOfParameters() = 2 and
    (
      this.getDeclaringType()
          .getASourceSupertype*()
          .hasQualifiedName(["org.apache.http", "org.apache.hc.core5.http"], "HttpMessage")
      or
      this.getDeclaringType()
          .getASourceSupertype*()
          .hasQualifiedName("org.apache.http.client.methods", "RequestBuilder")
      or
      this.getDeclaringType()
          .getASourceSupertype*()
          .hasQualifiedName("org.apache.hc.core5.http.support", "AbstractMessageBuilder")
    )
  }
}

/** A constructor of an Apache HttpCore `BasicHeader`. */
class ApacheBasicHeaderConstructor extends Constructor {
  ApacheBasicHeaderConstructor() {
    this.getDeclaringType()
        .hasQualifiedName(["org.apache.http.message", "org.apache.hc.core5.http.message"],
          "BasicHeader")
  }
}

/** A header name or value passed to an outgoing Apache HttpClient request. */
class OutgoingRequestHeaderSink extends DataFlow::Node {
  OutgoingRequestHeaderSink() {
    exists(Call c |
      (
        c.getCallee() instanceof ApacheHttpClientSetHeaderMethod or
        c.getCallee() instanceof ApacheBasicHeaderConstructor
      ) and
      this.asExpr() = c.getArgument([0, 1])
    )
  }
}

/**
 * A taint-tracking configuration for user input flowing into a header of an
 * outgoing HTTP client request. Sources and barriers are shared with
 * `java/http-response-splitting`.
 */
module OutgoingRequestHeaderSplittingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { ResponseSplittingConfig::isSource(source) }

  predicate isSink(DataFlow::Node sink) { sink instanceof OutgoingRequestHeaderSink }

  predicate isBarrier(DataFlow::Node node) { ResponseSplittingConfig::isBarrier(node) }
}

module OutgoingRequestHeaderSplittingFlow =
  TaintTracking::Global<OutgoingRequestHeaderSplittingConfig>;

import OutgoingRequestHeaderSplittingFlow::PathGraph

from
  OutgoingRequestHeaderSplittingFlow::PathNode source,
  OutgoingRequestHeaderSplittingFlow::PathNode sink
where OutgoingRequestHeaderSplittingFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This outgoing request header depends on a $@, which may allow header injection or request splitting.",
  source.getNode(), "user-provided value"
