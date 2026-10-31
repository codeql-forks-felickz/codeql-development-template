/**
 * @name Permissive CORS configuration
 * @description Allowing any origin to read cross-origin responses lets an
 *              arbitrary website read data served to a victim's browser.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id rust/permissive-cors
 * @tags security
 *       external/cwe/cwe-942
 */

import rust

/** Holds if `e` is a string literal whose value is `value`. */
bindingset[value]
private predicate isStringLiteral(Expr e, string value) {
  e.(StringLiteralExpr).getTextValue() = "\"" + value + "\""
}

/**
 * Gets an expression that the value of `e` is syntactically derived from: a
 * receiver or argument of a call, a parenthesized, referenced or `?`-operand
 * expression, or the initializer of a local variable read by `e`.
 *
 * This handles wrappers such as `"*".parse::<HeaderValue>().unwrap()`,
 * `HeaderValue::from_static("*")` and `let origin = "*"; ... origin`.
 */
private Expr getAnInnerExpr(Expr e) {
  result = e.(MethodCallExpr).getReceiver()
  or
  result = e.(MethodCallExpr).getArgList().getAnArg()
  or
  result = e.(CallExpr).getArgList().getAnArg()
  or
  result = e.(ParenExpr).getExpr()
  or
  result = e.(RefExpr).getExpr()
  or
  result = e.(TryExpr).getExpr()
  or
  exists(Variable v, LetStmt let |
    e = v.getAnAccess() and
    let.getPat() = v.getPat() and
    result = let.getInitializer()
  )
}

/** Holds if `p` is a path whose final segment is `name` (for example `Any` or `cors::Any`). */
bindingset[name]
private predicate pathEndsWith(Path p, string name) { p.getText() = name }

/**
 * Holds if `p` is a path whose final segment is `name` and whose qualifier
 * ends in `qualifier` (for example `CorsLayer::permissive`).
 */
bindingset[qualifier, name]
private predicate qualifiedPathEndsWith(Path p, string qualifier, string name) {
  p.getText() = name and
  p.getQualifier().getText() = qualifier
}

/** Holds if `c` is a call to a function at a path ending in `qualifier::name`. */
bindingset[qualifier, name]
private predicate isPathCall(CallExpr c, string qualifier, string name) {
  qualifiedPathEndsWith(c.getFunction().(PathExpr).getPath(), qualifier, name)
}

/** Holds if `e` is (or is derived from) a value denoting the wildcard CORS origin. */
private predicate isWildcardOriginValue(Expr e) {
  isStringLiteral(e, "*")
  or
  // `tower_http::cors::Any`, `salvo::cors::Any`
  pathEndsWith(e.(PathExpr).getPath(), "Any")
  or
  // `tower_http::cors::AllowOrigin::any()`, `AllowOrigin::mirror_request()`
  isPathCall(e, "AllowOrigin", ["any", "mirror_request"])
  or
  isWildcardOriginValue(getAnInnerExpr(e))
}

/** Holds if `e` names (or is derived from a name of) the `Access-Control-Allow-Origin` header. */
private predicate isAllowOriginHeaderName(Expr e) {
  e.(StringLiteralExpr).getTextValue().toLowerCase() = "\"access-control-allow-origin\""
  or
  pathEndsWith(e.(PathExpr).getPath(), "ACCESS_CONTROL_ALLOW_ORIGIN")
  or
  isAllowOriginHeaderName(getAnInnerExpr(e))
}

/**
 * Holds if `name` and `value` are an adjacent header name/value pair, either
 * consecutive arguments of a call (for example `headers.insert(name, value)`
 * or `with_header(reply, name, value)`) or a 2-tuple `(name, value)`.
 */
private predicate isHeaderPair(Expr pair, Expr name, Expr value) {
  exists(ArgList args, int i |
    args = pair.(MethodCallExpr).getArgList() or args = pair.(CallExpr).getArgList()
  |
    name = args.getArg(i) and
    value = args.getArg(i + 1)
  )
  or
  pair.(TupleExpr).getNumberOfFields() = 2 and
  name = pair.(TupleExpr).getField(0) and
  value = pair.(TupleExpr).getField(1)
}

/**
 * Holds if `e` configures a CORS policy (or sets a CORS response header) that
 * allows any origin, described by `description`.
 */
predicate isPermissiveCors(Expr e, string description) {
  // warp: `warp::cors().allow_any_origin()`; actix-cors: `Cors::default().allow_any_origin()`
  e.(MethodCallExpr).getIdentifier().getText() = "allow_any_origin" and
  e.(MethodCallExpr).getArgList().getNumberOfArgs() = 0 and
  description = "This CORS policy allows any origin"
  or
  // tower-http / salvo: `.allow_origin(Any)`, `.allow_origin("*".parse().unwrap())`
  e.(MethodCallExpr).getIdentifier().getText() = "allow_origin" and
  isWildcardOriginValue(e.(MethodCallExpr).getArgList().getArg(0)) and
  description = "This CORS policy allows any origin"
  or
  // actix-cors: `Cors::permissive()`; tower-http: `CorsLayer::permissive()` / `very_permissive()`
  (
    isPathCall(e, "Cors", "permissive")
    or
    isPathCall(e, "CorsLayer", ["permissive", "very_permissive"])
    or
    // rocket_cors: `AllowedOrigins::all()`
    isPathCall(e, "AllowedOrigins", "all")
  ) and
  description = "This CORS policy allows any origin"
  or
  // iron / hyper 0.10: `AccessControlAllowOrigin::Any`
  qualifiedPathEndsWith(e.(PathExpr).getPath(), "AccessControlAllowOrigin", "Any") and
  description = "This Access-Control-Allow-Origin header allows any origin"
  or
  // raw header: `headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, "*")`, `("Access-Control-Allow-Origin", "*")`
  exists(Expr name, Expr value |
    isHeaderPair(e, name, value) and
    isAllowOriginHeaderName(name) and
    isWildcardOriginValue(value)
  ) and
  description = "This Access-Control-Allow-Origin header allows any origin"
}

from Expr e, string description
where isPermissiveCors(e, description)
select e,
  description + ", so any website can read responses from this service in a victim's browser."
