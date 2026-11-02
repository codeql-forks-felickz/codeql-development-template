/**
 * @name URL redirection from remote source (extended)
 * @description URL redirection based on unvalidated user input may cause
 *              redirection to malicious web sites. Extends
 *              `java/unvalidated-url-redirection` with Spring redirect view
 *              names, Spring `Location` response headers and scheme-relative
 *              (`"/" + input`) redirect targets.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id java/custom/unvalidated-url-redirection
 * @tags security
 *       external/cwe/cwe-601
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.ExternalFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.controlflow.Guards
import semmle.code.java.frameworks.spring.SpringController
import semmle.code.java.security.RequestForgery
import semmle.code.java.security.Sanitizers
import semmle.code.java.security.UrlRedirect

/** Holds if `e` is the compile-time constant header name `Location`. */
private predicate isLocationHeaderName(Expr e) {
  e.(CompileTimeConstantExpr).getStringValue().toLowerCase() = "location"
}

/** Holds if `t` is Spring's `HttpHeaders` or a subtype of it. */
private predicate isSpringHttpHeadersType(Type t) {
  t.(RefType).getASourceSupertype*().hasQualifiedName("org.springframework.http", "HttpHeaders")
}

/**
 * Holds if `e` is a Spring `HttpHeaders` object, including one that is held in a variable
 * declared as a `MultiValueMap`.
 */
private predicate isSpringHttpHeaders(Expr e) {
  isSpringHttpHeadersType(e.getType())
  or
  exists(ClassInstanceExpr cie |
    isSpringHttpHeadersType(cie.getConstructedType()) and
    DataFlow::localExprFlow(cie, e)
  )
}

/**
 * Holds if `add` is the concatenation `"redirect:" + e` (optionally `"redirect:/" + e`),
 * so that `e` controls the host of a Spring redirect view.
 */
private predicate isSpringRedirectViewConcat(AddExpr add, Expr e) {
  add.getLeftOperand().(CompileTimeConstantExpr).getStringValue().regexpMatch("redirect:[/\\\\]*") and
  e = add.getRightOperand()
}

/** Holds if `viewName` is used as a Spring MVC view name. */
private predicate isSpringViewName(Expr viewName) {
  exists(ReturnStmt r |
    viewName = r.getExpr() and
    not exists(SpringRequestMappingMethod m |
      m = r.getEnclosingCallable() and m.isResponseBody()
    )
  )
  or
  exists(ClassInstanceExpr cie |
    cie.getConstructedType().hasQualifiedName("org.springframework.web.servlet", "ModelAndView") and
    viewName = cie.getArgument(0) and
    viewName.getType() instanceof TypeString
  )
  or
  exists(MethodCall ma |
    ma.getMethod()
        .hasQualifiedName("org.springframework.web.servlet", "ModelAndView", "setViewName") and
    viewName = ma.getArgument(0)
  )
}

/**
 * The host-controlling part of a Spring `"redirect:" + input` view name that is returned from a
 * method or passed to a `ModelAndView`.
 */
private class SpringRedirectViewNameSink extends UrlRedirectSink {
  SpringRedirectViewNameSink() {
    exists(AddExpr add, Expr viewName |
      isSpringRedirectViewConcat(add, this.asExpr()) and
      TaintTracking::localExprTaint(add, viewName) and
      isSpringViewName(viewName)
    )
  }
}

/** A value written to a Spring `Location` response header. */
private class SpringLocationHeaderSink extends UrlRedirectSink {
  SpringLocationHeaderSink() {
    exists(MethodCall ma | this.asExpr() = ma.getArgument(1) |
      // headers.add("Location", url), headers.set("Location", url), headers.put("Location", urls)
      isSpringHttpHeaders(ma.getQualifier()) and
      ma.getMethod().hasName(["add", "set", "put"]) and
      isLocationHeaderName(ma.getArgument(0))
      or
      // ResponseEntity.status(...).header("Location", url)
      ma.getMethod()
          .getDeclaringType()
          .getSourceDeclaration()
          .hasQualifiedName("org.springframework.http", "ResponseEntity$HeadersBuilder") and
      ma.getMethod().hasName("header") and
      isLocationHeaderName(ma.getArgument(0))
    )
    or
    // headers.get("Location").add(url)
    exists(MethodCall add, MethodCall get |
      add.getQualifier() = get and
      add.getMethod().hasName(["add", "set"]) and
      this.asExpr() = add.getArgument(add.getNumArgument() - 1) and
      get.getMethod().hasName("get") and
      isSpringHttpHeaders(get.getQualifier()) and
      isLocationHeaderName(get.getArgument(0))
    )
    or
    exists(MethodCall ma | this.asExpr() = ma.getArgument(0) |
      // headers.setLocation(uri)
      ma.getMethod().hasQualifiedName("org.springframework.http", "HttpHeaders", "setLocation")
      or
      // ResponseEntity.status(...).location(uri)
      ma.getMethod()
          .getDeclaringType()
          .getSourceDeclaration()
          .hasQualifiedName("org.springframework.http", "ResponseEntity$HeadersBuilder") and
      ma.getMethod().hasName("location")
    )
  }
}

/**
 * Holds if `node` is appended after the constant `"/"`, as in `"/" + input` or
 * `new StringBuilder("/").append(input)`.
 *
 * The standard `HostnameSanitizingPrefix` treats a bare `"/"` prefix as fixing the host, which is
 * true for request URLs but not for redirect targets: `"/" + "/evil.example"` is the
 * scheme-relative URL `//evil.example`. Expressions that also follow another hostname-sanitizing
 * prefix (for example `"/app/"`) are not affected.
 */
private predicate isSchemeRelativeRedirectTarget(DataFlow::Node node) {
  node.asExpr() =
    any(HostnameSanitizingPrefix p | p.getStringValue() = "/").getAnAppendedExpression() and
  not node.asExpr() =
    any(HostnameSanitizingPrefix p | p.getStringValue() != "/").getAnAppendedExpression()
}

private predicate isContainsUrlSanitizer(Guard guard, Expr e, boolean branch) {
  guard =
    any(MethodCall method |
      method.getMethod().getName() = "contains" and
      e = method.getArgument(0) and
      branch = true
    )
}

/** Holds if `guard` checks that `e` equals a compile-time constant string. */
private predicate isConstantEqualityGuard(Guard guard, Expr e, boolean branch) {
  exists(MethodCall eq |
    guard = eq and
    eq.getMethod().getDeclaringType() instanceof TypeString and
    eq.getMethod().hasName(["equals", "equalsIgnoreCase"]) and
    branch = true
  |
    e = eq.getQualifier() and eq.getArgument(0) instanceof CompileTimeConstantExpr
    or
    e = eq.getArgument(0) and eq.getQualifier() instanceof CompileTimeConstantExpr
  )
}

/**
 * Holds if `node` is a barrier for URL redirection, other than a bare `"/"` hostname prefix.
 */
private predicate isNonPrefixRedirectBarrier(DataFlow::Node node) {
  node instanceof SimpleTypeSanitizer or
  node instanceof RegexpCheckBarrier or
  node = DataFlow::BarrierGuard<isContainsUrlSanitizer/3>::getABarrierNode() or
  barrierNode(node, ["request-forgery", "url-redirection"])
}

module ExtendedUrlRedirectConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof UrlRedirectSink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof UrlRedirectSanitizer and not isSchemeRelativeRedirectTarget(node)
    or
    isSchemeRelativeRedirectTarget(node) and isNonPrefixRedirectBarrier(node)
    or
    // A value that is known to equal a constant string cannot redirect to an arbitrary host.
    node = DataFlow::BarrierGuard<isConstantEqualityGuard/3>::getABarrierNode()
  }
}

module ExtendedUrlRedirectFlow = TaintTracking::Global<ExtendedUrlRedirectConfig>;

import ExtendedUrlRedirectFlow::PathGraph

from ExtendedUrlRedirectFlow::PathNode source, ExtendedUrlRedirectFlow::PathNode sink
where ExtendedUrlRedirectFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Untrusted URL redirection depends on a $@.", source.getNode(),
  "user-provided value"
