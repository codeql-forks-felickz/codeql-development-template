/**
 * @name Open URL redirect (extended call graph)
 * @description Open URL redirection based on unvalidated user input
 *              may cause redirection to malicious web sites. This variant of
 *              `go/unvalidated-url-redirection` also follows taint into functions
 *              that are invoked through function-typed struct fields, and treats
 *              gin's `Context.Redirect` as a redirect sink.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision high
 * @id go/custom/unvalidated-url-redirection
 * @tags security
 *       external/cwe/cwe-601
 */

import go
import semmle.go.security.OpenUrlRedirect
import semmle.go.security.SafeUrlFlow
import lib.FunctionFieldCallTaintStep
import OpenUrlRedirect::Flow::PathGraph

from OpenUrlRedirect::Flow::PathNode source, OpenUrlRedirect::Flow::PathNode sink
where
  OpenUrlRedirect::Flow::flowPath(source, sink) and
  // this excludes flow from safe parts of request URLs, for example the full URL when the
  // doing a redirect from `http://<path>` to `https://<path>`. Unlike the standard query, only
  // flow from this particular source is considered, so that a sink that is reached both by a safe
  // part of the request URL and by some other untrusted value is still reported for the latter.
  not SafeUrlFlow::Flow::flow(source.getNode(), sink.getNode())
select sink.getNode(), source, sink, "This path to an untrusted URL redirection depends on a $@.",
  source.getNode(), "user-provided value"
