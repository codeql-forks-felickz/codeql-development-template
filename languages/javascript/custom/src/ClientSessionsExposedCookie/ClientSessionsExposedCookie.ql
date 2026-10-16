/**
 * @name Sensitive client-sessions cookie exposed to the client
 * @description Session cookies set by the `client-sessions` middleware can be read by
 *              client-side JavaScript if the `httpOnly` flag is disabled.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision high
 * @id js/client-sessions-exposed-cookie
 * @tags security
 *       external/cwe/cwe-1004
 */

import javascript
import frameworks.ClientSessions

from ClientSessions::SessionCookieWrite cookie
where
  cookie.isSensitive() and
  cookie.isServerSide() and
  not cookie.isHttpOnly()
select cookie, "Sensitive server cookie is missing 'httpOnly' flag."
