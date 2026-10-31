/**
 * @name URL redirection from remote source
 * @description URL redirection based on unvalidated user input
 *              may cause redirection to malicious web sites. In addition
 *              to the standard redirect APIs, this version also treats
 *              values written to a `Location` response header (for example
 *              via `http.server` `send_header`) as redirect locations.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @sub-severity low
 * @id py/url-redirection
 * @tags security
 *       external/cwe/cwe-601
 * @precision high
 */

import python
import semmle.python.security.dataflow.UrlRedirectQuery
import UrlRedirectFlow::PathGraph
import UrlRedirectLocationHeader
import CapturedUnpackedVariableTaint

from UrlRedirectFlow::PathNode source, UrlRedirectFlow::PathNode sink
where UrlRedirectFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Untrusted URL redirection depends on a $@.", source.getNode(),
  "user-provided value"
