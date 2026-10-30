/**
 * @name MySQL connection allows multiple statements per query
 * @description Enabling `multiStatements` in the `github.com/go-sql-driver/mysql` driver lets a
 *              single query string execute several semicolon-separated statements, which turns
 *              any SQL injection into arbitrary stacked-query execution.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id go/mysql-multi-statements-enabled
 * @tags security
 *       external/cwe/cwe-089
 */

import go

/** Gets the import path of the MySQL driver. */
private string mysqlDriver() { result = "github.com/go-sql-driver/mysql" }

/** Holds if `v` is a DSN parameter value the driver parses as `true`. */
bindingset[v]
private predicate isTrueParamValue(string v) { v = ["1", "true", "TRUE", "True"] }

/** Holds if `base` is a map that is (or is stored in) the `Params` field of a `mysql.Config`. */
private predicate isConfigParamsMap(DataFlow::Node base) {
  exists(Field params | params.hasQualifiedName(mysqlDriver(), "Config", "Params") |
    exists(DataFlow::FieldReadNode read |
      read.getField() = params and
      DataFlow::localFlow(read, base)
    )
    or
    exists(Write w, DataFlow::Node rhs |
      w.writesFieldPreUpdate(_, params, rhs) and
      DataFlow::localFlow(base, rhs)
    )
  )
}

/** Holds if `n` enables multi-statement support on the MySQL driver; `how` describes the mechanism. */
predicate enablesMultiStatements(DataFlow::Node n, string how) {
  exists(Write w, DataFlow::Node base, DataFlow::Node key |
    w.writesElementPreUpdate(base, key, n) and
    isConfigParamsMap(base) and
    key.getStringValue() = "multiStatements" and
    isTrueParamValue(n.getStringValue()) and
    how = "mysql.Config.Params[\"multiStatements\"]"
  )
  or
  exists(Write w, Field f |
    f.hasQualifiedName(mysqlDriver(), "Config", "MultiStatements") and
    w.writesFieldPreUpdate(_, f, n) and
    n.asExpr().getBoolValue() = true and
    how = "mysql.Config.MultiStatements"
  )
  or
  exists(StringLit lit | lit = n.asExpr() |
    lit.getValue().regexpMatch("(?s)(.*[?&])?multiStatements=(1|true|TRUE|True)(&.*)?") and
    how = "the DSN parameter multiStatements"
  )
}

from DataFlow::Node n, string how
where enablesMultiStatements(n, how)
select n,
  "Multiple statements per query are enabled via " + how +
    ", allowing SQL injection to execute stacked statements."
