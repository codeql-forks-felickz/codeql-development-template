/**
 * @name Weak CORS, CSP or framing security headers
 * @description Response headers that allow inline or evaluated scripts, that let other sites
 *              frame a page, or that accept cross-origin requests from any origin weaken the
 *              browser-side protections against cross-site scripting, clickjacking and
 *              cross-origin data access.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.4
 * @precision medium
 * @id java/cors-csp-security-headers
 * @tags security
 *       external/cwe/cwe-693
 *       external/cwe/cwe-942
 *       external/cwe/cwe-1021
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.controlflow.Guards

/** Gets the compile-time constant string that flows locally to `e`, if any. */
pragma[nomagic]
private string constantString(Expr e) {
  exists(CompileTimeConstantExpr c |
    DataFlow::localExprFlow(c, e) and
    result = c.getStringValue()
  )
}

/** A call that writes an HTTP response header, such as `HttpServletResponse.setHeader`. */
private class HeaderWrite extends MethodCall {
  HeaderWrite() {
    this.getNumArgument() >= 2 and
    this.getArgument(0).getType() instanceof TypeString and
    (
      this.getMethod().hasName(["setHeader", "addHeader", "header"])
      or
      this.getMethod().hasName(["add", "set"]) and
      this.getMethod()
          .getDeclaringType()
          .getSourceDeclaration()
          .hasQualifiedName("org.springframework.http", "HttpHeaders")
    )
  }

  /** Gets the lower-case name of the header written by this call. */
  string getHeaderName() { result = constantString(this.getArgument(0)).toLowerCase() }

  /** Gets the constant value of the header written by this call. */
  string getHeaderValue() { result = constantString(this.getArgument(1)) }
}

/**
 * Holds if `c` sets an enforced Content-Security-Policy whose constant value is `policy`, either as
 * a raw response header or through Spring Security's `HeadersConfigurer`.
 */
private predicate cspPolicy(MethodCall c, string policy) {
  c.(HeaderWrite).getHeaderName() = "content-security-policy" and
  policy = c.(HeaderWrite).getHeaderValue()
  or
  c.getMethod().hasName(["contentSecurityPolicy", "policyDirectives"]) and
  c.getMethod()
      .getDeclaringType()
      .getSourceDeclaration()
      .getQualifiedName()
      .matches("org.springframework.security.config.%") and
  policy = constantString(c.getArgument(0))
}

/** Gets the lower-case source list of the `directive` directive of the CSP `policy`. */
bindingset[policy]
private string directiveSources(string policy, string directive) {
  exists(string d |
    d = policy.splitAt(";").trim() and
    directive = d.regexpCapture("([A-Za-z-]+)(\\s.*)?", 1).toLowerCase() and
    result = d.suffix(directive.length()).trim().toLowerCase()
  )
}

/** Holds if the CSP source list `sources` contains `token`. */
bindingset[sources]
private predicate hasSource(string sources, string token) {
  token = sources.regexpFind("\\S+", _, _)
}

/**
 * Gets the source list that controls script execution for `policy`: `script-src` if present,
 * otherwise the `default-src` fallback.
 */
bindingset[policy]
private string scriptSources(string policy, string directive) {
  directive = "script-src" and
  result = directiveSources(policy, directive)
  or
  directive = "default-src" and
  result = directiveSources(policy, directive) and
  not exists(directiveSources(policy, "script-src"))
}

/**
 * Holds if `sources` contains `'unsafe-inline'` and it is not ignored by the browser because of a
 * nonce, a hash or `'strict-dynamic'`.
 */
bindingset[sources]
private predicate effectiveUnsafeInline(string sources) {
  hasSource(sources, "'unsafe-inline'") and
  not exists(string t |
    hasSource(sources, t) and
    t.regexpMatch("'(nonce-|sha256-|sha384-|sha512-).*|'strict-dynamic'")
  )
}

/** Holds if `c` sets a CSP that allows inline or evaluated scripts. */
private predicate weakCsp(MethodCall c, string msg) {
  exists(string policy, string directive, string sources, string unsafe |
    cspPolicy(c, policy) and
    sources = scriptSources(policy, directive) and
    unsafe =
      concat(string k |
        k = "'unsafe-inline'" and effectiveUnsafeInline(sources)
        or
        k = "'unsafe-eval'" and hasSource(sources, k)
      |
        k, " and "
      ) and
    unsafe != "" and
    msg =
      "Content-Security-Policy allows " + unsafe + " scripts through its " + directive +
        " directive, which defeats its protection against cross-site scripting."
  )
}

/** Holds if `c` writes an `X-Frame-Options` header with value `value`. */
private predicate xFrameOptions(HeaderWrite c, string value) {
  c.getHeaderName() = "x-frame-options" and
  value = c.getHeaderValue()
}

/** Holds if `value` is an `X-Frame-Options` value that browsers enforce. */
bindingset[value]
private predicate validXFrameOptions(string value) {
  value.trim().toUpperCase() = ["DENY", "SAMEORIGIN"]
}

/** Gets the `frame-ancestors` source list of the CSP set by `c`. */
private string frameAncestors(MethodCall c) {
  exists(string policy |
    cspPolicy(c, policy) and
    result = directiveSources(policy, "frame-ancestors")
  )
}

/** Holds if the `frame-ancestors` source list `sources` allows any site to frame the page. */
bindingset[sources]
private predicate permissiveFrameAncestors(string sources) {
  hasSource(sources, ["*", "http:", "https:"])
}

/** Holds if `c` writes an `X-Frame-Options` header or a CSP with a `frame-ancestors` directive. */
private predicate framingHeaderWrite(MethodCall c) {
  xFrameOptions(c, _) or exists(frameAncestors(c))
}

/** Holds if `c` writes a framing header that browsers enforce and that restricts framing. */
private predicate framingProtection(MethodCall c) {
  exists(string v | xFrameOptions(c, v) and validXFrameOptions(v))
  or
  exists(string s | s = frameAncestors(c) and not permissiveFrameAncestors(s))
}

/** Holds if `c` writes a framing header that does not prevent framing by other sites. */
private predicate ineffectiveFraming(MethodCall c, string msg) {
  exists(string v |
    xFrameOptions(c, v) and
    not validXFrameOptions(v) and
    msg =
      "X-Frame-Options is set to '" + v +
        "', which browsers do not enforce, so the page can be framed by any site (clickjacking)."
  )
  or
  permissiveFrameAncestors(frameAncestors(c)) and
  msg = "Content-Security-Policy frame-ancestors allows any site to frame the page (clickjacking)."
}

/** A call that reads the path of the current request. */
private class RequestPathCall extends MethodCall {
  RequestPathCall() {
    this.getMethod().hasName(["getRequestURI", "getRequestURL", "getServletPath", "getPathInfo"]) and
    this.getMethod().getDeclaringType().getASupertype*().getName().matches("%Request")
  }
}

/** Holds if framing protection written by `c` is only applied for some request paths. */
private predicate pathConditionalFraming(MethodCall c, string msg) {
  framingProtection(c) and
  exists(ConditionBlock cb, Expr sub |
    cb.controls(c.getBasicBlock(), _) and
    sub.getParent*() = cb.getCondition() and
    TaintTracking::localExprTaint(any(RequestPathCall p), sub)
  ) and
  msg =
    "Framing protection is only applied when a request-path condition holds, so responses for the excluded paths can be framed by any site (clickjacking)."
}

/** Holds if `t` is Spring Security's `HeadersConfigurer.FrameOptionsConfig`. */
private predicate frameOptionsConfigType(RefType t) {
  t.getSourceDeclaration()
      .hasQualifiedName("org.springframework.security.config.annotation.web.configurers",
        "HeadersConfigurer$FrameOptionsConfig")
}

/** Holds if `t` is Spring Security's `HeadersConfigurer`. */
private predicate headersConfigurerType(RefType t) {
  t.getSourceDeclaration()
      .hasQualifiedName("org.springframework.security.config.annotation.web.configurers",
        "HeadersConfigurer")
}

/**
 * Holds if `c` disables Spring Security's `X-Frame-Options` header. This includes the call that the
 * extractor synthesizes for a method reference such as `FrameOptionsConfig::disable`.
 */
private predicate springFramingDisabled(MethodCall c, string msg) {
  exists(RefType t |
    c.getMethod().hasName("disable") and
    t = c.getQualifier().getType()
  |
    frameOptionsConfigType(t) and
    msg =
      "Spring Security's X-Frame-Options header is disabled, so pages can be framed by any site (clickjacking)."
    or
    headersConfigurerType(t) and
    msg =
      "All Spring Security response headers, including X-Frame-Options, are disabled, so pages can be framed by any site (clickjacking)."
  )
}

/** Holds if `m` is a public, annotated web request handler method. */
private predicate isRequestHandler(Method m) {
  m.fromSource() and
  m.isPublic() and
  exists(m.getBody()) and
  exists(AnnotationType a | a = m.getAnAnnotation().getType() |
    a.getName().matches("%Mapping") or
    a.hasName(["GET", "POST", "PUT", "DELETE", "PATCH"])
  )
}

/** Holds if request handler `m`, or a method it calls, writes the framing header `c`. */
pragma[nomagic]
private predicate handlerWritesFramingHeader(Method m, MethodCall c) {
  isRequestHandler(m) and
  framingHeaderWrite(c) and
  m.calls*(c.getEnclosingCallable())
}

/**
 * Holds if request handler `m` writes no framing header although `sibling`, another handler in the
 * same class, protects its response against framing.
 */
private predicate inconsistentFraming(Method m, string msg) {
  isRequestHandler(m) and
  not handlerWritesFramingHeader(m, _) and
  exists(string sibling |
    sibling =
      min(Method p, MethodCall c |
        p.getDeclaringType() = m.getDeclaringType() and
        p != m and
        handlerWritesFramingHeader(p, c) and
        framingProtection(c)
      |
        p.getName()
      ) and
    msg =
      "Request handler '" + m.getName() +
        "' sets no X-Frame-Options or CSP frame-ancestors header, unlike handler '" + sibling +
        "' in the same class, so its response can be framed by any site (clickjacking)."
  )
}

/** Holds if `t` is a Spring MVC or WebFlux `CorsRegistration`. */
private predicate corsRegistrationType(RefType t) {
  t.getSourceDeclaration()
      .hasQualifiedName([
          "org.springframework.web.servlet.config.annotation",
          "org.springframework.web.reactive.config"
        ], "CorsRegistration")
}

/** A `CorsRegistry.addMapping` call, which starts a registration that allows any origin. */
private class AddCorsMapping extends MethodCall {
  AddCorsMapping() {
    this.getMethod().hasName("addMapping") and
    corsRegistrationType(this.getType())
  }
}

/** Gets an expression that refers to the CORS registration created by `add`. */
private Expr registrationRef(AddCorsMapping add) {
  result = add
  or
  exists(MethodCall c |
    c.getQualifier() = registrationRef(add) and
    corsRegistrationType(c.getType()) and
    result = c
  )
  or
  DataFlow::localExprFlow(registrationRef(add), result)
}

/** Holds if `c` configures the allowed origins of the CORS registration created by `add`. */
private predicate originConfig(AddCorsMapping add, MethodCall c) {
  c.getQualifier() = registrationRef(add) and
  c.getMethod().hasName(["allowedOrigins", "allowedOriginPatterns"])
}

/** Holds if `add` registers a CORS mapping that accepts requests from any origin. */
private predicate permissiveCorsMapping(AddCorsMapping add, string msg) {
  exists(string mapping, string reason |
    (
      if exists(constantString(add.getArgument(0)))
      then mapping = "'" + constantString(add.getArgument(0)) + "'"
      else mapping = "this path pattern"
    ) and
    (
      exists(MethodCall c | originConfig(add, c) and constantString(c.getAnArgument()) = "*") and
      reason = "allows every origin ('*')"
      or
      not originConfig(add, _) and
      reason = "leaves its allowed origins at the permissive default ('*')"
    ) and
    msg =
      "The CORS mapping for " + mapping + " " + reason +
        ", so any website can make cross-origin requests to these endpoints and read the responses."
  )
}

/** Holds if `c` allows every origin on a programmatic Spring `CorsConfiguration`. */
private predicate permissiveCorsConfiguration(MethodCall c, string msg) {
  c.getMethod().hasName(["addAllowedOrigin", "addAllowedOriginPattern"]) and
  c.getMethod()
      .getDeclaringType()
      .getSourceDeclaration()
      .hasQualifiedName("org.springframework.web.cors", "CorsConfiguration") and
  constantString(c.getArgument(0)) = "*" and
  msg =
    "This CORS configuration allows every origin ('*'), so any website can make cross-origin requests and read the responses."
}

from Element e, string msg
where
  weakCsp(e, msg) or
  ineffectiveFraming(e, msg) or
  pathConditionalFraming(e, msg) or
  springFramingDisabled(e, msg) or
  inconsistentFraming(e, msg) or
  permissiveCorsMapping(e, msg) or
  permissiveCorsConfiguration(e, msg)
select e, msg
