/**
 * @name Stored cross-site scripting
 * @description Writing data that was read from a database to a web page without
 *              encoding it allows an attacker who can store data (for example a
 *              comment or a product name) to run script in other users' browsers.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision medium
 * @id cs/web/stored-xss
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import csharp
import StoredXss
import StoredXssFlow::PathGraph

from StoredXssFlow::PathNode source, StoredXssFlow::PathNode sink
where StoredXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This HTML or JavaScript write depends on a $@ that may contain stored user input.",
  source.getNode(), "stored value"
