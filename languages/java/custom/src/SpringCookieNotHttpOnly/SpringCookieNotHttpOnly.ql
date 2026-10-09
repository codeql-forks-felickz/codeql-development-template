/**
 * @name Sensitive Spring ResponseCookie without the HttpOnly flag set
 * @description A sensitive cookie created with Spring's `ResponseCookie` builder without the
 *              'HttpOnly' flag set may be vulnerable to an XSS attack.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @security-severity 5.0
 * @id java/spring-sensitive-cookie-not-httponly
 * @tags security
 *       external/cwe/cwe-1004
 */

/*
 * Complements the upstream `java/sensitive-cookie-not-httponly` query, which only models servlet
 * `Cookie` objects and raw servlet `Set-Cookie` headers. This query tracks cookie names that
 * appear to be sensitive into `ResponseCookie.from(name, ...)`, through the builder, to a
 * `Set-Cookie` header or a WebFlux `addCookie` call, and reports it if the builder never calls
 * `.httpOnly(true)`.
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import Cookies.SpringCookies

/** Gets a regular expression for matching common names of sensitive cookies. */
string getSensitiveCookieNameRegex() { result = "(?i).*(auth|session|token|key|credential).*" }

/** Gets a regular expression for matching CSRF cookies. */
string getCsrfCookieNameRegex() { result = "(?i).*(csrf|xsrf).*" }

/**
 * Holds if a string is concatenated with the name of a sensitive cookie. Excludes CSRF cookies
 * since they implement the Synchronizer Token Pattern and are meant to be read by JavaScript.
 */
predicate isSensitiveCookieNameExpr(Expr expr) {
  exists(string s | s = expr.(CompileTimeConstantExpr).getStringValue() |
    s.regexpMatch(getSensitiveCookieNameRegex()) and not s.regexpMatch(getCsrfCookieNameRegex())
  )
  or
  isSensitiveCookieNameExpr(expr.(AddExpr).getAnOperand())
}

/**
 * A taint-tracking configuration for sensitive cookie names that are used to create a
 * `ResponseCookie` that is written to an HTTP response.
 */
module SensitiveResponseCookieConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isSensitiveCookieNameExpr(source.asExpr()) }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof CookieResponseSink }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(ResponseCookieCreation create |
      pred.asExpr() = create.getNameArgument() and
      succ.asExpr() = create
    )
    or
    responseCookieStep(pred, succ)
  }
}

module SensitiveResponseCookieFlow = TaintTracking::Global<SensitiveResponseCookieConfig>;

from CookieResponseSink sink
where
  SensitiveResponseCookieFlow::flowToExpr(sink) and
  ResponseCookieToResponseFlow::flowToExpr(sink) and
  not HttpOnlyResponseCookie::flowsTo(sink)
select sink.getCall(),
  "Sensitive cookie is added to response without the 'HttpOnly' flag being set."
