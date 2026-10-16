/**
 * @name Uncontrolled data used in path expression (extended deep link models)
 * @description Accessing paths influenced by users can allow an attacker to access unexpected resources.
 *              This variant of `swift/path-injection` adds models for parsing custom URL scheme
 *              (deep link) query parameters and for deep links stored on view controllers.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id swift/path-injection-extended
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 *       external/cwe/cwe-099
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.security.PathInjectionQuery
import PathInjectionModels
import PathInjectionFlow::PathGraph

from PathInjectionFlow::PathNode source, PathInjectionFlow::PathNode sink
where PathInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This path depends on a $@.", source.getNode(),
  "user-provided value"
