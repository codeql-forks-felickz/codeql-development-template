/**
 * Runs the logic of the standard `java/unsafe-deserialization` query against the test database,
 * so that the data extensions in `languages-java-custom-models` are validated against it.
 */

import java
import semmle.code.java.security.UnsafeDeserializationQuery
import UnsafeDeserializationFlow::PathGraph

from UnsafeDeserializationFlow::PathNode source, UnsafeDeserializationFlow::PathNode sink
where UnsafeDeserializationFlow::flowPath(source, sink)
select sink.getNode().(UnsafeDeserializationSink).getMethodCall(), source, sink,
  "Unsafe deserialization depends on a $@.", source.getNode(), "user-provided value"
