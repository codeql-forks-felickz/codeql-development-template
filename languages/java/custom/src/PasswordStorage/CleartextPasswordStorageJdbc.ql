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

/** Holds if a prepared-statement parameter is in an INSERT value or UPDATE assignment. */
bindingset[sql, position]
private predicate isWriteSqlParameter(string sql, int position) {
  exists(string normalized |
    normalized = sql.toLowerCase() and
    (
      exists(int valuesStart |
        normalized.regexpMatch("^\\s*(insert|replace)\\b.*\\bvalues\\b.*") and
        valuesStart = normalized.indexOf("values") and
        not normalized.substring(0, valuesStart).regexpMatch("(?s).*\\?.*") and
        hasAtLeastSqlParameters(normalized.substring(valuesStart, normalized.length()), position)
      )
      or
      exists(int setStart, int valuesEnd |
        normalized.regexpMatch("^\\s*update\\b.*\\bset\\b.*") and
        setStart = normalized.indexOf("set") and
        valuesEnd = getUpdateSetEnd(normalized, setStart) and
        not normalized.substring(0, setStart).regexpMatch("(?s).*\\?.*") and
        hasAtLeastSqlParameters(normalized.substring(setStart, valuesEnd), position)
      )
    )
  )
}

/** Holds if `sql` contains at least `minCount` parameter markers. */
bindingset[sql, minCount]
private predicate hasAtLeastSqlParameters(string sql, int minCount) {
  minCount > 0 and
  sql.regexpMatch("(?s)(?:[^?]*\\?){" + minCount.toString() + ",}.*")
}

/** Gets the end of the UPDATE SET clause, before WHERE when present. */
bindingset[sql, setStart]
private int getUpdateSetEnd(string sql, int setStart) {
  exists(int whereStart |
    whereStart = sql.indexOf("where") and
    whereStart > setStart and
    result = whereStart
  )
  or
  not exists(int whereStart | whereStart = sql.indexOf("where") and whereStart > setStart) and
  result = sql.length()
}

/** Holds if a concatenated password value occurs in an INSERT value or UPDATE assignment. */
private predicate isConcatenatedWriteValue(Expr value) {
  exists(AddExpr concatenation, MethodCall execute, StringLiteral prefix |
    concatenation.getRightOperand() = value and
    TaintTracking::localExprTaint(prefix, concatenation.getLeftOperand()) and
    prefix.getValue()
        .regexpMatch("(?is).*(\\b(insert|replace)\\b.*\\bvalues\\b|\\bupdate\\b.*\\bset\\b).*") and
    not exists(StringLiteral wherePrefix |
      TaintTracking::localExprTaint(wherePrefix, concatenation.getLeftOperand()) and
      wherePrefix.getValue().regexpMatch("(?is).*\\bwhere\\b.*")
    ) and
    execute.getMethod().hasName(["execute", "executeUpdate", "executeLargeUpdate", "addBatch"]) and
    execute.getMethod()
        .getDeclaringType()
        .getASourceSupertype*()
        .hasQualifiedName("java.sql", "Statement") and
    isWriteSql(execute.getArgument(0)) and
    TaintTracking::localExprTaint(concatenation, execute.getArgument(0))
  )
}

/** A value that is written to a database with an SQL `INSERT` or `UPDATE`. */
class DatabaseWriteSink extends Expr {
  DatabaseWriteSink() {
    // stmt.executeUpdate("INSERT ... '" + password + "'")
    isConcatenatedWriteValue(this)
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
      isWriteSql(prepare.getArgument(0)) and
      exists(StringLiteral sql |
        TaintTracking::localExprTaint(sql, prepare.getArgument(0)) and
        isWriteSqlParameter(
          sql.getValue(),
          set.getArgument(0).(CompileTimeConstantExpr).getIntValue()
        )
      )
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
