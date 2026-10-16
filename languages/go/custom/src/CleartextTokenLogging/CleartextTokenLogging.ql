/**
 * @name Clear-text logging of authentication tokens
 * @description Logging a signed JWT, access token, refresh token or session token
 *              exposes an active credential to anyone who can read the logs.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id go/clear-text-logging-token
 * @tags security
 *       external/cwe/cwe-312
 *       external/cwe/cwe-315
 *       external/cwe/cwe-359
 *       external/cwe/cwe-532
 */

import go
import CleartextTokenLoggingQuery
import CleartextTokenLogging::Flow::PathGraph

from CleartextTokenLogging::Flow::PathNode source, CleartextTokenLogging::Flow::PathNode sink
where CleartextTokenLogging::Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "$@ flows to a logging call.", source.getNode(),
  "An authentication token from " + source.getNode().(CleartextTokenLogging::Source).describe()
