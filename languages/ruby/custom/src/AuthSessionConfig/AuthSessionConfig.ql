/**
 * @name Insecure authentication session cookie configuration
 * @description Session or authentication cookies that are sent without the `Secure`
 *              attribute can be leaked over cleartext HTTP, and cookies without the
 *              `HttpOnly` attribute can be read by client-side scripts.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id rb/insecure-session-cookie
 * @tags security
 *       external/cwe/cwe-614
 *       external/cwe/cwe-1004
 */

import codeql.ruby.AST

/** Gets the value of the `key` option passed in the call `call`, if any. */
Expr getOption(Call call, string key) {
  exists(Pair p |
    p = call.getAnArgument().(Pair) or p = call.getAnArgument().(HashLiteral).getAnElement()
  |
    p.getKey().getConstantValue().isStringlikeValue(key) and
    result = p.getValue()
  )
}

/** Holds if the options passed to `call` may include entries that are not statically known. */
predicate hasUnknownOptions(Call call) {
  call.getAnArgument() instanceof HashSplatExpr or
  call.getAnArgument().(HashLiteral).getAnElement() instanceof HashSplatExpr
}

/** Holds if `e` is the literal `false` or `nil`. */
predicate isFalsy(Expr e) {
  e instanceof BooleanLiteral and e.(BooleanLiteral).isFalse()
  or
  e instanceof NilLiteral
}

/** Holds if the application enables `config.force_ssl`, which marks all cookies as `Secure`. */
predicate forcesSsl() {
  exists(AssignExpr a |
    a.getLeftOperand().(MethodCall).getMethodName() = "force_ssl" and
    a.getRightOperand().(BooleanLiteral).isTrue()
  )
}

/** A call to `config.session_store` that configures the Rails session cookie. */
class SessionStoreCall extends MethodCall {
  SessionStoreCall() {
    this.getMethodName() = "session_store" and
    this.getReceiver().(MethodCall).getMethodName() = "config" and
    not this.getArgument(0).getConstantValue().isStringlikeValue("disabled")
  }

  /** Holds if positional options cannot be inspected statically. */
  predicate hasUnknownPositionalOptions() {
    exists(int i, Expr options |
      i > 0 and
      options = this.getArgument(i) and
      not options instanceof Pair and
      not options instanceof Literal
    )
  }
}

/** A call to `set_cookie` that sets a session or authentication cookie. */
class SetSessionCookieCall extends MethodCall {
  SetSessionCookieCall() {
    this.getMethodName() = "set_cookie" and
    this.getNumberOfArguments() >= 2 and
    this.getArgument(0)
        .getConstantValue()
        .getStringlikeValue()
        .regexpMatch("(?i).*(sess|auth|token|login|remember|jwt|credential).*|(?i)(.*_)?sid")
  }

  /** Holds if the cookie attributes are passed as a hash literal or as keyword arguments. */
  predicate hasOptionsHash() {
    this.getArgument(1) instanceof Pair or this.getArgument(1) instanceof HashLiteral
  }

  /** Holds if the cookie value is passed directly as a string, without any attributes. */
  predicate isPlainValue() { this.getArgument(1) instanceof StringlikeLiteral }
}

/**
 * Holds if `call` configures a session cookie for which `attribute` is
 * missing or disabled, as described by `reason`.
 */
predicate insecureAttribute(Call call, string attribute, string reason) {
  attribute = ["secure", "httponly"] and
  (
    call instanceof SessionStoreCall and
    (
      isFalsy(getOption(call, attribute)) and reason = "disabled"
      or
      attribute = "secure" and
      not exists(getOption(call, attribute)) and
      not hasUnknownOptions(call) and
      not call.(SessionStoreCall).hasUnknownPositionalOptions() and
      not forcesSsl() and
      reason = "missing"
    )
    or
    exists(SetSessionCookieCall c | c = call |
      c.isPlainValue() and reason = "missing"
      or
      c.hasOptionsHash() and
      (
        isFalsy(getOption(c, attribute)) and reason = "disabled"
        or
        not exists(getOption(c, attribute)) and
        not hasUnknownOptions(c) and
        reason = "missing"
      )
    )
  )
}

/** Gets the display name of the cookie attribute `attribute`. */
string attributeName(string attribute) {
  attribute = "secure" and result = "Secure"
  or
  attribute = "httponly" and result = "HttpOnly"
}

/** Gets a description of the cookie configured by `call`. */
string describe(Call call) {
  call instanceof SessionStoreCall and result = "Session store cookie"
  or
  call instanceof SetSessionCookieCall and
  result = "Cookie '" + call.getArgument(0).getConstantValue().getStringlikeValue() + "'"
}

from Call call, string issues
where
  issues =
    strictconcat(string attribute, string reason |
      insecureAttribute(call, attribute, reason)
    |
      "the " + attributeName(attribute) + " attribute is " + reason, " and "
    )
select call, describe(call) + " is insecure: " + issues + "."
