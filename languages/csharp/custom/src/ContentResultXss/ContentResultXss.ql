/**
 * @name Cross-site scripting through an HTML ContentResult
 * @description Returning user-controlled data in an ASP.NET Core `ContentResult` that is
 *              served as HTML, without encoding it, allows an attacker to run script in
 *              the victim's browser.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id cs/web/content-result-xss
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import csharp
import ContentResultXss
import ContentResultXssFlow::PathGraph

from ContentResultXssFlow::PathNode source, ContentResultXssFlow::PathNode sink
where ContentResultXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This HTML response body depends on a $@ and is not HTML encoded.", source.getNode(),
  "user-provided value"
