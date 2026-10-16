/**
 * @name Clear-text password stored in a database
 * @description Writing a password to a database with an SQL INSERT or UPDATE statement
 *              without first hashing it with a password hashing function exposes every
 *              account if the database is read by an attacker.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id py/cleartext-password-storage-sql
 * @tags security
 *       external/cwe/cwe-256
 *       external/cwe/cwe-312
 */

import python
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.SensitiveDataSources

/**
 * Holds if `sql` is an SQL statement that writes to a password column.
 */
bindingset[sql]
predicate isPasswordWriteSql(string sql) {
  sql.regexpMatch("(?is)\\s*(insert|replace)\\s+into\\b.*\\bpass(word|wd)?\\b.*")
  or
  sql.regexpMatch("(?is)\\s*update\\b.*\\bset\\b.*\\bpass(word|wd)?\\s*=.*")
}

/** Gets the concatenated text of the literal parts of the f-string `f`. */
string fstringText(Fstring f) {
  result = concat(int i, StringLiteral part | part = f.getValue(i) | part.getText() order by i)
}

/**
 * A string built from an SQL template that writes to a password column, such as
 * `"INSERT INTO users (name, password) VALUES ('%s', '%s')" % (name, pw)`.
 */
class PasswordWriteSqlConstruction extends DataFlow::Node {
  PasswordWriteSqlConstruction() {
    exists(BinaryExpr fmt |
      fmt.getOp() instanceof Mod and
      isPasswordWriteSql(fmt.getLeft().(StringLiteral).getText()) and
      this.asExpr() = fmt
    )
    or
    exists(DataFlow::MethodCallNode fmt |
      fmt.calls(any(DataFlow::Node lit | isPasswordWriteSql(lit.asExpr().(StringLiteral).getText())),
        "format") and
      this = fmt
    )
    or
    isPasswordWriteSql(fstringText(this.asExpr()))
  }
}

/**
 * A parameter value passed to a parameterized SQL statement that writes to a password
 * column, such as `cursor.execute("UPDATE users SET password = ?", (pw,))`.
 */
class PasswordWriteSqlParameter extends DataFlow::Node {
  PasswordWriteSqlParameter() {
    exists(SqlExecution exec, DataFlow::Node sql, StringLiteral lit |
      sql = exec.getSql() and
      DataFlow::localFlow(DataFlow::exprNode(lit), sql) and
      isPasswordWriteSql(lit.getText()) and
      this = exec.(DataFlow::CallCfgNode).getArg(_) and
      this != sql
    )
  }
}

/** Holds if `call` calls a function whose name suggests that it hashes or encrypts its input. */
predicate isHashingCall(DataFlow::CallCfgNode call) {
  exists(string name |
    name = call.getFunction().(DataFlow::AttrRead).getAttributeName()
    or
    name = call.getFunction().asCfgNode().(NameNode).getId()
  |
    name.regexpMatch("(?i).*(hash|crypt|digest|derive|kdf|argon).*")
  )
}

module CleartextPasswordStorageSqlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.(SensitiveDataSource).getClassification() = SensitiveDataClassification::password()
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof PasswordWriteSqlConstruction or
    sink instanceof PasswordWriteSqlParameter
  }

  predicate isBarrier(DataFlow::Node node) {
    isHashingCall(node) or
    node = any(Cryptography::CryptographicOperation op).(DataFlow::Node)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module CleartextPasswordStorageSqlFlow = TaintTracking::Global<CleartextPasswordStorageSqlConfig>;

import CleartextPasswordStorageSqlFlow::PathGraph

from
  CleartextPasswordStorageSqlFlow::PathNode source, CleartextPasswordStorageSqlFlow::PathNode sink
where CleartextPasswordStorageSqlFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This SQL statement stores a $@ in the database without hashing it.", source.getNode(), "password"
