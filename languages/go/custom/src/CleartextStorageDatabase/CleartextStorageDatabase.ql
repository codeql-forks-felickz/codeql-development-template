/**
 * @name Cleartext storage of sensitive information in a database
 * @description Writing personal data (such as social security numbers, dates of birth or
 *              salaries) or passwords to a database without hashing or encryption exposes
 *              it to anyone who can read the database or a backup of it.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id go/cleartext-storage-database
 * @tags security
 *       external/cwe/cwe-312
 *       external/cwe/cwe-359
 */

import go
import semmle.go.security.SensitiveActions

/**
 * Gets a regular expression matching names that indicate personal data which
 * should not be stored in cleartext.
 */
string privateDataRegexp() {
  result =
    [
      "(?is).*(social.?security|salary|salaries|date.?of.?birth|birth.?date|birthday|credit.?card|card.?num|bank.?account|passport.?(no|num)).*",
      // snake_case or lowercase abbreviations, e.g. `ssn`, `user_dob`
      "(?i)(.*_)?(ssn|dob)(_.*)?",
      // CamelCase abbreviations, e.g. `SSN`, `UserSsn`, `DOB`
      "(.*[a-z0-9])?(SSN|Ssn|DOB|Dob)([A-Z_0-9].*)?"
    ]
}

/** Holds if `name` suggests that it refers to personal data stored in cleartext. */
bindingset[name]
predicate isPrivateDataName(string name) {
  name.regexpMatch(privateDataRegexp()) and
  not name.regexpMatch(HeuristicNames::notSensitive())
}

/** A data flow node that likely holds sensitive data. */
class SensitiveDataSource extends DataFlow::Node {
  string description;

  SensitiveDataSource() {
    exists(Variable v | this = v.getARead() |
      isPrivateDataName(v.getName()) and
      description = v.getName() and
      not exists(ProtectingCall c | DataFlow::localFlow(c.getResult(_), this))
    )
    or
    exists(DataFlow::CallNode call | this = call.getResult() |
      isPrivateDataName(call.getCalleeName()) and description = call.getCalleeName()
      or
      exists(string s | s = call.getAnArgument().getStringValue() |
        s.regexpMatch("(?i)[a-z_][a-z_0-9]*") and
        not call.getTarget().hasQualifiedName("fmt", "Sprintf") and
        not exists(SQL::QueryString qs | qs = call.getAnArgument()) and
        isPrivateDataName(s) and description = s
      )
    )
    or
    exists(SensitiveExpr e | this.asExpr() = e |
      e.getClassification() = [SensitiveExpr::password(), SensitiveExpr::secret()] and
      description = e.getClassification()
    )
  }

  /** Gets a short description of the sensitive data. */
  string getDescription() { result = description }
}

/**
 * A call whose result is a hashed, encrypted or otherwise protected version of
 * its input.
 */
class ProtectingCall extends DataFlow::CallNode {
  ProtectingCall() {
    exists(string name | name = this.getCalleeName() |
      name.regexpMatch(HeuristicNames::notSensitive()) or
      name.regexpMatch("(?i)(.*(digest|hmac|argon2|scrypt|pbkdf2|frompassword).*|sum(\\d+.*)?|seal)")
    )
  }
}

/** Holds if `text` is derived from a SQL statement that writes data. */
predicate isSqlWriteText(DataFlow::Node text) {
  exists(DataFlow::Node lit |
    lit.getStringValue().regexpMatch("(?is)\\s*(insert|update|replace|upsert|merge)\\s.*") and
    TaintTracking::localTaint(lit, text)
  )
}

/**
 * Holds if `call` executes a SQL statement that writes data, and `arg` is either
 * the statement text or one of its bind parameters.
 */
predicate sqlWriteArgument(DataFlow::CallNode call, DataFlow::Node arg) {
  // `db.Exec(query, args...)` and similar: the query string and every argument after it.
  exists(SQL::QueryString qs, int i, int j |
    qs = call.getSyntacticArgument(i) and
    isSqlWriteText(qs) and
    arg = call.getSyntacticArgument(j) and
    j >= i
  )
  or
  // `stmt, _ := db.Prepare(query); stmt.Exec(args...)`
  exists(DataFlow::MethodCallNode prepare, string m, SQL::QueryString qs |
    prepare
        .getTarget()
        .hasQualifiedName("database/sql", ["DB", "Tx", "Conn"], ["Prepare", "PrepareContext"]) and
    qs = prepare.getASyntacticArgument() and
    isSqlWriteText(qs) and
    DataFlow::localFlow(prepare.getResult(0), call.(DataFlow::MethodCallNode).getReceiver()) and
    call.(DataFlow::MethodCallNode).getTarget().hasQualifiedName("database/sql", "Stmt", m) and
    m = ["Exec", "ExecContext", "Query", "QueryContext", "QueryRow", "QueryRowContext"] and
    arg = call.getASyntacticArgument()
  )
}

module CleartextStorageDatabaseConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof SensitiveDataSource }

  predicate isSink(DataFlow::Node sink) { sqlWriteArgument(_, sink) }

  predicate isBarrier(DataFlow::Node node) { node = any(ProtectingCall c).getResult(_) }

  predicate isBarrierIn(DataFlow::Node node) {
    // only report the closest source on a path
    isSource(node)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module CleartextStorageDatabaseFlow = TaintTracking::Global<CleartextStorageDatabaseConfig>;

import CleartextStorageDatabaseFlow::PathGraph

from CleartextStorageDatabaseFlow::PathNode source, CleartextStorageDatabaseFlow::PathNode sink
where CleartextStorageDatabaseFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This SQL statement stores $@ in cleartext.", source.getNode(),
  "sensitive data (" + source.getNode().(SensitiveDataSource).getDescription() + ")"
