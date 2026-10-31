/**
 * @name Sensitive Spring cookie without the HttpOnly flag set
 * @description A sensitive Spring cookie without the 'HttpOnly' flag set may be vulnerable to an
 *              XSS attack.
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
 * `Cookie` objects and raw servlet `Set-Cookie` headers. This query tracks sensitive names into
 * Spring `ResponseCookie` builders and raw `Set-Cookie` values written with `HttpHeaders.put`.
 * It reports a cookie if the builder never calls `.httpOnly(true)` or a raw value lacks the
 * `HttpOnly` attribute.
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import Cookies.SpringCookies

/** Gets a regular expression for matching common names of sensitive cookies. */
string getSensitiveCookieNameRegex() { result = "(?i).*(auth|session|token|key|credential).*" }

/** Gets a regular expression for matching CSRF cookies. */
string getCsrfCookieNameRegex() { result = "(?i).*(csrf|xsrf).*" }

private predicate isCsrfCookieNameExpr(Expr expr) {
  exists(string s | s = expr.(CompileTimeConstantExpr).getStringValue() |
    s.regexpMatch(getCsrfCookieNameRegex())
  )
}

/**
 * Holds if a string is concatenated with the name of a sensitive cookie. Excludes CSRF cookies
 * since they implement the Synchronizer Token Pattern and are meant to be read by JavaScript.
 */
predicate isSensitiveCookieNameExpr(Expr expr) {
  exists(string s | s = expr.(CompileTimeConstantExpr).getStringValue() |
    s.regexpMatch(getSensitiveCookieNameRegex()) and not s.regexpMatch(getCsrfCookieNameRegex())
  )
  or
  not isCsrfCookieNameExpr(expr) and
  isSensitiveCookieNameExpr(expr.(AddExpr).getAnOperand())
}

/**
 * A taint-tracking configuration for sensitive names used to create a `ResponseCookie` or a raw
 * `Set-Cookie` value that is written to an HTTP response.
 */
module SensitiveResponseCookieConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isSensitiveCookieNameExpr(source.asExpr()) }

  predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof CookieResponseSink
    or
    sink.asExpr() instanceof SpringHttpHeadersPutSetCookieValue
  }

  predicate isBarrier(DataFlow::Node node) { isCsrfCookieNameExpr(node.asExpr()) }

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

/** A taint-tracking configuration for string constants containing the `HttpOnly` attribute. */
private module RawHttpOnlyAttributeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr()
        .(CompileTimeConstantExpr)
        .getStringValue()
        .regexpMatch("(?is).*(?:^|;)\\s*httponly\\s*(?:;|$).*")
  }

  predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof SpringHttpHeadersPutSetCookieValue
  }

  predicate observeDiffInformedIncrementalMode() {
    none() // only used negatively
  }
}

private module RawHttpOnlyAttributeFlow = TaintTracking::Global<RawHttpOnlyAttributeConfig>;

from MethodCall call
where
  exists(CookieResponseSink sink |
    SensitiveResponseCookieFlow::flowToExpr(sink) and
    ResponseCookieToResponseFlow::flowToExpr(sink) and
    not HttpOnlyResponseCookie::flowsTo(sink) and
    call = sink.getCall()
  )
  or
  exists(SpringHttpHeadersPutSetCookieValue value |
    SensitiveResponseCookieFlow::flowToExpr(value) and
    not RawHttpOnlyAttributeFlow::flowToExpr(value) and
    call = value.getCall()
  )
select call,
  "Sensitive cookie is added to response without the 'HttpOnly' flag being set."
