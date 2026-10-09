/**
 * @name Deserialization of user-controlled data (extended)
 * @description Deserializing user-controlled data may allow attackers to execute arbitrary code.
 *              Extends `py/unsafe-deserialization` with additional taint propagation through
 *              `urllib.parse.unquote_to_bytes`, which is commonly used to decode raw request
 *              query parameters before passing them to `pickle.loads`.
 * @kind path-problem
 * @id py/custom/unsafe-deserialization
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags external/cwe/cwe-502
 *       security
 *       serialization
 */

import python
import semmle.python.ApiGraphs
import semmle.python.security.dataflow.UnsafeDeserializationQuery
import UnsafeDeserializationFlow::PathGraph

/**
 * A taint step through `urllib.parse.unquote_to_bytes`, which percent-decodes its
 * (string or bytes) argument and returns the decoded bytes.
 *
 * See https://docs.python.org/3/library/urllib.parse.html#urllib.parse.unquote_to_bytes
 */
private class UnquoteToBytesTaintStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(API::CallNode call |
      call = API::moduleImport("urllib").getMember("parse").getMember("unquote_to_bytes").getACall() and
      nodeFrom = call.getParameter(0, "string").asSink() and
      nodeTo = call
    )
  }
}

from UnsafeDeserializationFlow::PathNode source, UnsafeDeserializationFlow::PathNode sink
where UnsafeDeserializationFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe deserialization depends on a $@.", source.getNode(),
  "user-provided value"
