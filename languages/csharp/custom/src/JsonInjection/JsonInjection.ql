/**
 * @name JSON injection
 * @description Building JSON text by concatenating user-controlled values lets a malicious user
 *              change the structure of the JSON document, for example to add or override
 *              properties.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision high
 * @id cs/json-injection
 * @tags security
 *       external/cwe/cwe-074
 *       external/cwe/cwe-116
 */

import csharp
import JsonInjection
import JsonInjectionFlow::PathGraph

from JsonInjectionFlow::PathNode source, JsonInjectionFlow::PathNode sink
where JsonInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This JSON text depends on a $@.", source.getNode(),
  "user-provided value"
