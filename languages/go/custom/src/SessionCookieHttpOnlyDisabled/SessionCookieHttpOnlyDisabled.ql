/**
 * @name Sensitive cookie without HttpOnly
 * @description Sensitive cookies without the `HttpOnly` attribute can be read by client-side
 *              scripts, so a cross-site scripting flaw can expose authentication or authorization state.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @security-severity 5.0
 * @id go/session-cookie-httponly-disabled
 * @tags security
 *       external/cwe/cwe-1004
 */

import go
import semmle.go.concepts.HTTP
import semmle.go.security.CookieWithoutHttpOnly

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

private string echoPackagePath() { result = package("github.com/labstack/echo", "") }

/** A cookie written through Echo's `Context.SetCookie` method. */
private class EchoCookieWrite extends Http::CookieWrite::Range, DataFlow::MethodCallNode {
  EchoCookieWrite() {
    this.getTarget().hasQualifiedName(echoPackagePath(), "Context", "SetCookie")
  }

  override DataFlow::Node getName() { result = this.getArgument(0) }

  override DataFlow::Node getValue() { result = this.getArgument(0) }

  override DataFlow::Node getSecure() { result = this.getArgument(0) }

  override DataFlow::Node getHttpOnly() { result = this.getArgument(0) }
}

private module AdditionalCookieNameConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr().getStringValue().toLowerCase() in ["level", "uid"]
    or
    source.asExpr().(Name).getTarget().getName().toLowerCase() in ["level", "uid"]
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Http::CookieWrite cookie | sink = cookie.getName())
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Http::CookieOptionWrite option |
      option.getName() = pred and
      option.getCookieOutput() = succ
    )
  }
}

private module AdditionalCookieNameFlow = TaintTracking::Global<AdditionalCookieNameConfig>;

from DataFlow::Node alert
where
  exists(Write w, SessionOptionsHttpOnlyField f, DataFlow::Node rhs |
    alert = rhs and
    w.writesField(_, f, rhs) and
    exists(DataFlow::Node falseValue |
      falseValue.asExpr().getBoolValue() = false and
      DataFlow::localFlow(falseValue, rhs)
    )
  )
  or
  exists(Http::CookieWrite cookie |
    alert = cookie and
    (
      exists(
        string name, SensitiveCookieNameFlow::PathNode source, SensitiveCookieNameFlow::PathNode sink
      |
        isSensitiveCookie(cookie, name, source, sink)
      )
      or AdditionalCookieNameFlow::flowTo(cookie.getName())
    ) and
    isNonHttpOnlyCookie(cookie)
  )
select alert,
  "This sensitive cookie does not set the 'HttpOnly' attribute, exposing its value to client-side scripts."
