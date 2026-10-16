/**
 * @name Cleartext storage of a password in a database
 * @description Writing a password to a database with an SQL `INSERT` or `UPDATE` without
 *              hashing it first exposes reusable credentials to anyone who can read
 *              the database.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id java/cleartext-password-storage-jdbc
 * @tags security
 *       external/cwe/cwe-256
 *       external/cwe/cwe-312
 */

import java
import semmle.code.java.dataflow.TaintTracking
import PasswordStorage

/** Holds if `sql` is built from a string literal that starts an SQL statement that writes data. */
predicate isWriteSql(Expr sql) {
  exists(StringLiteral lit |
    lit.getValue().regexpMatch("(?is)\\s*(insert|update|replace|merge)\\b.*") and
    TaintTracking::localExprTaint(lit, sql)
  )
}

/** A value that is written to a database with an SQL `INSERT` or `UPDATE`. */
class DatabaseWriteSink extends Expr {
  DatabaseWriteSink() {
    // stmt.executeUpdate("INSERT ... '" + password + "'")
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getASourceSupertype*()
          .hasQualifiedName("java.sql", "Statement") and
      mc.getMethod().hasName(["execute", "executeUpdate", "executeLargeUpdate", "addBatch"]) and
      this = mc.getArgument(0) and
      isWriteSql(this)
    )
    or
    // con.prepareStatement("INSERT ... (?)").setString(1, password)
    exists(MethodCall set, MethodCall prepare |
      set.getMethod()
          .getDeclaringType()
          .getASourceSupertype*()
          .hasQualifiedName("java.sql", "PreparedStatement") and
      set.getMethod().hasName(["setString", "setNString", "setObject", "setBytes"]) and
      this = set.getArgument(1) and
      prepare.getMethod().hasName(["prepareStatement", "prepareCall"]) and
      prepare
          .getMethod()
          .getDeclaringType()
          .getASourceSupertype*()
          .hasQualifiedName("java.sql", "Connection") and
      DataFlow::localExprFlow(prepare, set.getQualifier()) and
      isWriteSql(prepare.getArgument(0))
    )
  }
}

module CleartextPasswordStorageConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node.asExpr() instanceof PasswordExpr }

  predicate isSink(DataFlow::Node node) { node.asExpr() instanceof DatabaseWriteSink }

  predicate isBarrier(DataFlow::Node node) { isPasswordProtectionCall(node) }

  // Report each flow from the password access closest to the sink only.
  predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module CleartextPasswordStorageFlow = TaintTracking::Global<CleartextPasswordStorageConfig>;

import CleartextPasswordStorageFlow::PathGraph

from CleartextPasswordStorageFlow::PathNode source, CleartextPasswordStorageFlow::PathNode sink
where CleartextPasswordStorageFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This $@ is written to the database without being hashed with a password hashing function.",
  source.getNode(), "password"
