/**
 * @name Clear-text storage of password in database
 * @description Storing a password in a database without hashing it with a
 *              password hashing function exposes every user's credential if
 *              the database is disclosed.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id go/cleartext-password-storage-database
 * @tags security
 *       external/cwe/cwe-256
 *       external/cwe/cwe-312
 *       external/cwe/cwe-522
 */

import go
import CleartextPasswordStorageQuery
import CleartextPasswordStorage::Flow::PathGraph

from CleartextPasswordStorage::Flow::PathNode source, CleartextPasswordStorage::Flow::PathNode sink
where CleartextPasswordStorage::Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "This stores $@ in a database without hashing it.",
  source.getNode(),
  "a password from " + source.getNode().(CleartextPasswordStorage::Source).describe()
