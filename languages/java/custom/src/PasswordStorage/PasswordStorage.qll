/**
 * Provides classes and predicates for reasoning about how passwords are stored.
 */

import java
private import semmle.code.java.dataflow.DataFlow

/** Gets a regular expression matching names that suggest a password. */
private string passwordRegex() { result = "(?i).*(pass(wd|word|code|phrase)|pwd).*" }

/**
 * Gets a regular expression matching names that contain a password-like word but
 * that are unlikely to hold a cleartext password.
 */
private string nonPasswordRegex() {
  result =
    "(?i).*(hash|crypt|digest|salt|question|policy|length|hint|label|field|regex|pattern|prompt|url|expir).*"
}

bindingset[name]
private predicate isPasswordName(string name) {
  name.regexpMatch(passwordRegex()) and not name.regexpMatch(nonPasswordRegex())
}

/**
 * An expression that likely evaluates to a cleartext password, such as a read of a
 * variable named `password`, a call to `getPassword()`, or a lookup such as
 * `request.getParameter("password")`.
 */
class PasswordExpr extends Expr {
  PasswordExpr() {
    isPasswordName(this.(VarRead).getVariable().getName())
    or
    isPasswordName(this.(MethodCall).getMethod().getName()) and
    not this.(MethodCall).getMethod().getReturnType() instanceof BooleanType
    or
    isPasswordName(this.(MethodCall).getAnArgument().(StringLiteral).getValue())
  }
}

/**
 * Holds if `node` is the result of a call that likely hashes, encrypts or encodes a
 * password with a dedicated password encoder.
 */
predicate isPasswordProtectionCall(DataFlow::Node node) {
  exists(Method m | m = node.asExpr().(MethodCall).getMethod() |
    m.getName().regexpMatch("(?i).*(hash|digest|crypt|kdf|argon|scrypt).*")
    or
    m.hasName("encode") and
    m.getDeclaringType().getASupertype*().getName().matches("%PasswordEncoder")
  )
}
