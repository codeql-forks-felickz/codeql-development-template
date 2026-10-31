/**
 * @name Request headers sent to a user-controlled URL
 * @description Building a request that carries custom headers, such as an authorization token, for a URL that
 *              is controlled by a remote user (for example a deep link) sends those headers to an arbitrary host.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id swift/custom/request-headers-untrusted-url
 * @tags security
 *       external/cwe/cwe-200
 *       external/cwe/cwe-601
 */

import swift
import CredentialAndDataExposure.RequestHeadersToUntrustedUrl
import RequestHeadersToUntrustedUrlFlow::PathGraph

from
  RequestHeadersToUntrustedUrlFlow::PathNode source,
  RequestHeadersToUntrustedUrlFlow::PathNode sink, UrlRequestInitCall init, AstNode header
where
  RequestHeadersToUntrustedUrlFlow::flowPath(source, sink) and
  sink.getNode().asExpr() = init.getUrlArgument() and
  setsHeaderOn(init, header)
select sink.getNode(), source, sink,
  "This request URL depends on a $@ and the request carries a $@, which is sent to that host.",
  source.getNode(), "user-provided value", header, "custom header"
