/**
 * @name HTTP Response Splitting (extended)
 * @description Writing user input directly to an HTTP header
 *              makes code vulnerable to attack by header splitting.
 *              Extends `py/http-response-splitting` with flow through
 *              `dict.get` on dictionaries built from (key, value) pairs and
 *              through unpacked variables read from nested scopes.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id py/http-response-splitting-extended
 * @tags security
 *       external/cwe/cwe-113
 *       external/cwe/cwe-079
 */

import python
import semmle.python.security.dataflow.HttpHeaderInjectionQuery
import HeaderInjectionFlow::PathGraph
private import lib.CapturedUnpackedVariable
private import lib.DictGetUnknownKey

from HeaderInjectionFlow::PathNode source, HeaderInjectionFlow::PathNode sink
where HeaderInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This HTTP header is constructed from a $@.", source.getNode(),
  "user-provided value"
