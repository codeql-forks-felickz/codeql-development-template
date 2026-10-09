/**
 * Provides classes and predicates for reasoning about cookies created with Spring's
 * `org.springframework.http.ResponseCookie` builder, and about cookies written to an
 * HTTP response as a raw `Set-Cookie` header.
 */

import java
private import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.dataflow.TaintTracking
private import semmle.code.java.frameworks.Servlets

/** The class `org.springframework.http.ResponseCookie`. */
class SpringResponseCookie extends Class {
  SpringResponseCookie() { this.hasQualifiedName("org.springframework.http", "ResponseCookie") }
}

/** The interface `org.springframework.http.ResponseCookie$ResponseCookieBuilder`. */
class SpringResponseCookieBuilder extends Interface {
  SpringResponseCookieBuilder() {
    this.hasQualifiedName("org.springframework.http", "ResponseCookie$ResponseCookieBuilder")
  }
}

/** A call to `ResponseCookie.from(...)` or `ResponseCookie.fromClientResponse(...)`. */
class ResponseCookieCreation extends MethodCall {
  ResponseCookieCreation() {
    this.getMethod().getDeclaringType() instanceof SpringResponseCookie and
    this.getMethod().hasName(["from", "fromClientResponse"])
  }

  /** Gets the argument specifying the name of the cookie. */
  Expr getNameArgument() { result = this.getArgument(0) }
}

/** A call to `ResponseCookie.mutate()`, which copies the attributes of an existing cookie. */
class ResponseCookieMutateCall extends MethodCall {
  ResponseCookieMutateCall() {
    this.getMethod().getDeclaringType() instanceof SpringResponseCookie and
    this.getMethod().hasName("mutate")
  }
}

/** A call to a method of `ResponseCookie.ResponseCookieBuilder`, including `build()`. */
class ResponseCookieBuilderCall extends MethodCall {
  ResponseCookieBuilderCall() {
    this.getMethod().getDeclaringType().getAnAncestor() instanceof SpringResponseCookieBuilder
  }
}

/**
 * Holds if `call` sets the boolean cookie attribute `attribute` (for example `secure` or
 * `httpOnly`) to a value that is not known to be `false`.
 */
predicate setsResponseCookieAttribute(ResponseCookieBuilderCall call, string attribute) {
  call.getMethod().hasName(attribute) and
  call.getMethod().getNumberOfParameters() = 1 and
  call.getArgument(0).getType() instanceof BooleanType and
  not call.getArgument(0).(CompileTimeConstantExpr).getBooleanValue() = false
}

/** Holds if `call` sets the `Max-Age` of the cookie to zero, that is, it removes the cookie. */
predicate removesResponseCookie(ResponseCookieBuilderCall call) {
  call.getMethod().hasName("maxAge") and
  exists(Expr arg | arg = call.getArgument(0) |
    arg.(CompileTimeConstantExpr).getIntValue() = 0
    or
    arg.(LongLiteral).getValue().toInt() = 0
    or
    arg.(FieldAccess).getField().hasQualifiedName("java.time", "Duration", "ZERO")
  )
}

/**
 * Holds if there is a step from `pred` to `succ` through the `ResponseCookie` builder API,
 * or through a call to `ResponseCookie.toString()`.
 */
predicate responseCookieStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(ResponseCookieBuilderCall call |
    pred.asExpr() = call.getQualifier() and
    succ.asExpr() = call
  )
  or
  exists(MethodCall toString |
    toString.getMethod().hasName("toString") and
    toString.getMethod().getNumberOfParameters() = 0 and
    toString.getQualifier().getType().(RefType).getAnAncestor() instanceof SpringResponseCookie and
    pred.asExpr() = toString.getQualifier() and
    succ.asExpr() = toString
  )
}

/** Holds if `e` is the name of the `Set-Cookie` header. */
private predicate isSetCookieHeaderName(Expr e) {
  e.(CompileTimeConstantExpr).getStringValue().toLowerCase() = "set-cookie"
  or
  // `HttpHeaders.SET_COOKIE` from Spring, JAX-RS or Guava, whose constant value is not
  // available when the declaring library is only present as bytecode.
  exists(Field f | f = e.(FieldAccess).getField() |
    f.hasName("SET_COOKIE") and f.getDeclaringType().hasName("HttpHeaders")
  )
}

/**
 * The value argument of a call that adds a `Set-Cookie` header to an HTTP response, such as
 * `response.addHeader("Set-Cookie", value)`, `httpHeaders.add(HttpHeaders.SET_COOKIE, value)` or
 * `ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, value)`.
 */
class SetCookieHeaderValue extends Expr {
  MethodCall call;

  SetCookieHeaderValue() {
    isSetCookieHeaderName(call.getArgument(0)) and
    exists(Method m | m = call.getMethod().getSourceDeclaration() |
      (m instanceof ResponseAddHeaderMethod or m instanceof ResponseSetHeaderMethod) and
      this = call.getArgument(1)
      or
      m.getDeclaringType()
          .getAnAncestor()
          .hasQualifiedName("org.springframework.http", "HttpHeaders") and
      m.hasName(["add", "set"]) and
      this = call.getArgument(1)
      or
      m.getDeclaringType()
          .getAnAncestor()
          .hasQualifiedName("org.springframework.http", "ResponseEntity$HeadersBuilder") and
      m.hasName("header") and
      this = call.getArgument(any(int i | i >= 1))
    )
  }

  /** Gets the call that adds the `Set-Cookie` header. */
  MethodCall getCall() { result = call }
}

/**
 * An expression that is written to an HTTP response as a cookie: either the value of a
 * `Set-Cookie` header, or the argument of a WebFlux `ServerHttpResponse.addCookie(ResponseCookie)`
 * call.
 */
class CookieResponseSink extends Expr {
  MethodCall call;

  CookieResponseSink() {
    call = this.(SetCookieHeaderValue).getCall()
    or
    call.getMethod().hasName("addCookie") and
    call.getMethod()
        .getDeclaringType()
        .getAnAncestor()
        .hasQualifiedName("org.springframework.http.server.reactive", "ServerHttpResponse") and
    this = call.getArgument(0)
  }

  /** Gets the call that writes the cookie to the response. */
  MethodCall getCall() { result = call }
}

/** A taint-tracking configuration for `ResponseCookie`s that are written to an HTTP response. */
module ResponseCookieToResponseConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof ResponseCookieCreation }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof CookieResponseSink }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    responseCookieStep(pred, succ)
  }
}

/** Taint-tracking flow of `ResponseCookie`s that are written to an HTTP response. */
module ResponseCookieToResponseFlow = TaintTracking::Global<ResponseCookieToResponseConfig>;

/** Signature for predicates identifying calls that protect a `ResponseCookie`. */
signature predicate protectsResponseCookieSig(ResponseCookieBuilderCall call);

/**
 * Provides flow of `ResponseCookie` builders that are protected by a call satisfying
 * `protects` (for example `.secure(true)`), that remove the cookie with `.maxAge(0)`, or that
 * are derived from an existing cookie with `ResponseCookie.mutate()`.
 */
module ProtectedResponseCookie<protectsResponseCookieSig/1 protects> {
  private module Config implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) {
      exists(ResponseCookieBuilderCall call | protects(call) or removesResponseCookie(call) |
        // The fluent result, e.g. `from(..).secure(true).build()`, and the builder itself,
        // e.g. `builder.secure(true); builder.build()`.
        source.asExpr() = call or source.asExpr() = call.getQualifier()
      )
      or
      source.asExpr() instanceof ResponseCookieMutateCall
    }

    predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof CookieResponseSink }

    predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
      responseCookieStep(pred, succ)
    }

    predicate observeDiffInformedIncrementalMode() {
      none() // only used negatively
    }
  }

  private module Flow = TaintTracking::Global<Config>;

  /** Holds if a protected `ResponseCookie` flows to `sink`. */
  predicate flowsTo(CookieResponseSink sink) { Flow::flowToExpr(sink) }
}

/** Holds if `call` sets the `Secure` attribute of a `ResponseCookie`. */
predicate setsResponseCookieSecure(ResponseCookieBuilderCall call) {
  setsResponseCookieAttribute(call, "secure")
}

/** Holds if `call` sets the `HttpOnly` attribute of a `ResponseCookie`. */
predicate setsResponseCookieHttpOnly(ResponseCookieBuilderCall call) {
  setsResponseCookieAttribute(call, "httpOnly")
}

/** Flow of `ResponseCookie`s that have the `Secure` attribute set. */
module SecureResponseCookie = ProtectedResponseCookie<setsResponseCookieSecure/1>;

/** Flow of `ResponseCookie`s that have the `HttpOnly` attribute set. */
module HttpOnlyResponseCookie = ProtectedResponseCookie<setsResponseCookieHttpOnly/1>;

/**
 * Holds if `sink` receives a `ResponseCookie` created with `ResponseCookie.from(...)` whose
 * builder never sets the `Secure` attribute.
 */
predicate isResponseCookieWithoutSecure(CookieResponseSink sink) {
  ResponseCookieToResponseFlow::flowToExpr(sink) and
  not SecureResponseCookie::flowsTo(sink)
}

/** A taint-tracking configuration for string constants that look like a cookie (`name=value`). */
private module RawCookieStringConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr().(CompileTimeConstantExpr).getStringValue().matches("%=%")
  }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof SetCookieHeaderValue }
}

private module RawCookieStringFlow = TaintTracking::Global<RawCookieStringConfig>;

/** A taint-tracking configuration for string constants containing the `Secure` attribute. */
private module RawSecureAttributeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr().(CompileTimeConstantExpr).getStringValue().regexpMatch("(?is).*\\bsecure\\b.*")
  }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof SetCookieHeaderValue }

  predicate observeDiffInformedIncrementalMode() {
    none() // only used negatively
  }
}

private module RawSecureAttributeFlow = TaintTracking::Global<RawSecureAttributeConfig>;

/**
 * Holds if `value` is a raw `Set-Cookie` header value that is built from a `name=value` string
 * constant, is not derived from a `ResponseCookie`, and never contains the `Secure` attribute.
 */
predicate isRawSetCookieHeaderWithoutSecure(SetCookieHeaderValue value) {
  RawCookieStringFlow::flowToExpr(value) and
  not ResponseCookieToResponseFlow::flowToExpr(value) and
  not RawSecureAttributeFlow::flowToExpr(value)
}
