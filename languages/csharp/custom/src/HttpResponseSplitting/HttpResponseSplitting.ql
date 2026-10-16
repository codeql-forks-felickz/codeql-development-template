/**
 * @name HTTP response splitting
 * @description Writing user-controlled data into an HTTP response header without removing
 *              carriage return and line feed characters allows an attacker to inject
 *              additional headers or split the response.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision medium
 * @id cs/web/http-response-splitting
 * @tags security
 *       external/cwe/cwe-113
 *       external/cwe/cwe-079
 */

import csharp
import HttpResponseSplitting
import HttpResponseSplittingFlow::PathGraph

from HttpResponseSplittingFlow::PathNode source, HttpResponseSplittingFlow::PathNode sink
where HttpResponseSplittingFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This HTTP response header value depends on a $@." + headerCheckingNote(), source.getNode(),
  "user-provided value"
