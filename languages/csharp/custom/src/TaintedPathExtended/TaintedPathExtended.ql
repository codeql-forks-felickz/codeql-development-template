/**
 * @name Uncontrolled data used in path expression (extended)
 * @description Accessing paths influenced by users can allow an attacker to access unexpected resources.
 *              Extends `cs/path-injection` so that null checks and checks on a single character or the
 *              length of a path are not treated as path validation, and so that `path-injection` sinks
 *              from models-as-data are included.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id cs/path-injection-extended
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 *       external/cwe/cwe-099
 */

import csharp
import TaintedPathExtendedQuery
import TaintedPathExtended::PathGraph

from TaintedPathExtended::PathNode source, TaintedPathExtended::PathNode sink
where TaintedPathExtended::flowPath(source, sink)
select sink.getNode(), source, sink, "This path depends on a $@.", source.getNode(),
  "user-provided value"
