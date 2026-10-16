/**
 * @name Session cookie configured with HttpOnly disabled
 * @description Session cookies whose `HttpOnly` option is explicitly set to `false` can be read by
 *              client-side scripts, so a cross-site scripting flaw can be used to steal the session.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @security-severity 5.0
 * @id go/session-cookie-httponly-disabled
 * @tags security
 *       external/cwe/cwe-1004
 */

import go

/**
 * A field holding the `HttpOnly` option of a session-cookie configuration struct provided by
 * a session-management library (`gorilla/sessions` and `gin-contrib/sessions`).
 */
class SessionOptionsHttpOnlyField extends Field {
  SessionOptionsHttpOnlyField() {
    this.hasQualifiedName(package(["github.com/gorilla/sessions", "github.com/gin-contrib/sessions"],
        ""), "Options", "HttpOnly")
  }
}

/** Holds if `rhs` is a value that is always the boolean constant `false`. */
predicate isConstantFalse(DataFlow::Node rhs) {
  exists(DataFlow::Node falseValue |
    falseValue.asExpr().getBoolValue() = false and
    DataFlow::localFlow(falseValue, rhs)
  )
}

from Write w, SessionOptionsHttpOnlyField f, DataFlow::Node rhs
where
  w.writesField(_, f, rhs) and
  isConstantFalse(rhs)
select rhs,
  "The session cookie option 'HttpOnly' is set to false, exposing the session cookie to client-side scripts."
