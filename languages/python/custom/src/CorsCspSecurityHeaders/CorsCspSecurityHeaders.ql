/**
 * @name Permissive CORS or weak Content-Security-Policy configuration
 * @description Allowing any origin to read responses, trusting an overly permissive
 *              CORS origin pattern with credentials, or allowing inline scripts in a
 *              Content-Security-Policy weakens browser-enforced protections.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id py/cors-csp-security-headers
 * @tags security
 *       external/cwe/cwe-693
 *       external/cwe/cwe-942
 */

import python
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs
private import semmle.python.frameworks.Flask
private import semmle.python.frameworks.Werkzeug

/**
 * A `headers` attribute read on the response parameter of a Flask
 * `after_request` / `after_app_request` hook, such as `response.headers` in:
 *
 * ```python
 * @app.after_request
 * def add_headers(response):
 *     response.headers["Access-Control-Allow-Origin"] = "*"
 *     return response
 * ```
 */
private class FlaskAfterRequestResponseHeaders extends Werkzeug::Headers::InstanceSource {
  FlaskAfterRequestResponseHeaders() {
    exists(Function hook, DataFlow::ParameterNode response |
      hook.getADecorator() =
        [Flask::FlaskApp::instance(), Flask::Blueprint::instance()]
            .getMember(["after_request", "after_app_request"])
            .getAValueReachableFromSource()
            .asExpr() and
      response.getParameter() = hook.getArg(0) and
      this.(DataFlow::AttrRead).getObject().getALocalSource() = response and
      this.(DataFlow::AttrRead).getAttributeName() = "headers"
    )
  }
}

/** Gets the constant string value of `node`, if it is a string literal (possibly via local flow). */
string constantString(DataFlow::Node node) {
  result = node.asExpr().(StringLiteral).getText()
  or
  result = node.getALocalSource().asExpr().(StringLiteral).getText()
}

/** Holds if `write` sets the response header `name` (lower-cased) to the constant `value`. */
predicate headerWrite(Http::Server::ResponseHeaderWrite write, string name, string value) {
  name = constantString(write.getNameArg()).toLowerCase() and
  value = constantString(write.getValueArg())
}

/** Gets the `i`th directive (trimmed, lower-cased) of the single CSP policy `policy`. */
bindingset[policy]
string cspDirective(string policy, int i) {
  result = policy.splitAt(";", i).trim().toLowerCase() and result != ""
}

/** Gets the name of the CSP directive `directive`. */
bindingset[directive]
string cspDirectiveName(string directive) { result = directive.regexpCapture("([a-z-]+).*", 1) }

/**
 * Gets the effective directive named `name` in the CSP policy `policy`. Browsers
 * ignore all but the first occurrence of a directive.
 */
bindingset[policy]
string cspEffectiveDirective(string policy, string name) {
  exists(int i |
    result = cspDirective(policy, i) and
    name = cspDirectiveName(result) and
    not exists(int j | j < i and cspDirectiveName(cspDirective(policy, j)) = name)
  )
}

/**
 * Holds if the CSP `directive` allows inline scripts, that is, it contains
 * `'unsafe-inline'` and no well-formed nonce or hash source (which would make
 * browsers ignore `'unsafe-inline'`).
 */
bindingset[directive]
predicate directiveAllowsInlineScript(string directive) {
  directive.regexpMatch("(.*\\s)?'unsafe-inline'(\\s.*)?") and
  not directive.regexpMatch("(.*\\s)?'(nonce|sha256|sha384|sha512)-[a-z0-9+/_-]+=*'(\\s.*)?") and
  not directive.regexpMatch("(.*\\s)?'strict-dynamic'(\\s.*)?")
}

/** Holds if the single CSP policy `policy` allows inline scripts. */
bindingset[policy]
predicate policyAllowsInlineScript(string policy) {
  directiveAllowsInlineScript(cspEffectiveDirective(policy,
      ["script-src", "script-src-elem", "script-src-attr"]))
  or
  // `default-src` only applies to scripts when no `script-src` directive is present.
  directiveAllowsInlineScript(cspEffectiveDirective(policy, "default-src")) and
  not exists(cspEffectiveDirective(policy, "script-src"))
}

/** Holds if `policy` has a directive that applies to scripts. */
bindingset[policy]
predicate policyHasApplicableScriptDirective(string policy) {
  exists(string name |
    name = ["script-src", "script-src-elem", "script-src-attr", "default-src"] and
    exists(string directive | directive = cspEffectiveDirective(policy, name))
  )
}

/**
 * Holds if the Content-Security-Policy value `csp` allows inline scripts. A
 * comma-separated value contains several policies whose script directives
 * intersect. Policies without an applicable script directive do not restrict
 * inline scripts.
 */
bindingset[csp]
predicate cspAllowsInlineScript(string csp) {
  exists(string policy | policy = csp.splitAt(",") and policy.trim() != "") and
  exists(string policy |
    policy = csp.splitAt(",") and policy.trim() != "" and policyAllowsInlineScript(policy)
  ) and
  forall(string policy | policy = csp.splitAt(",") and policy.trim() != "" |
    policyAllowsInlineScript(policy) or not policyHasApplicableScriptDirective(policy)
  )
}

/**
 * Holds if `s` is a regular expression (fragment) that matches any origin, such as
 * `.*`, `^.+$`, `https://.*` or `https?://[^/]+`.
 */
bindingset[s]
predicate isCatchAllOriginRegex(string s) {
  s.regexpMatch("\\(?\\^?([a-z()|?]*://)?(\\.|\\[\\^[^\\].]*\\])[*+]\\??\\$?\\)?")
}

/** Holds if character `i` is a top-level alternative separator in `regex`. */
bindingset[regex]
private predicate isTopLevelRegexSeparator(string regex, int i) {
  exists(string prefix, string unescapedPrefix, string outsideClasses, string parentheses,
      string trailingBackslashes |
    i >= 0 and i < regex.length() and
    regex.charAt(i) = "|" and
    prefix = regex.substring(0, i) and
    trailingBackslashes = prefix.regexpCapture(".*(\\\\*)$", 1) and
    trailingBackslashes.length() % 2 = 0 and
    unescapedPrefix = prefix.regexpReplaceAll("\\\\.", "#") and
    outsideClasses =
      unescapedPrefix.regexpReplaceAll("\\[(\\\\.|[^\\]\\\\])*\\]", "#") and
    not outsideClasses.regexpMatch(".*\\[.*") and
    parentheses = outsideClasses.regexpReplaceAll("[^()]", "") and
    parentheses.regexpReplaceAll("\\)", "").length() =
      parentheses.regexpReplaceAll("\\(", "").length()
  )
}

/** Holds if `regex` has a catch-all top-level alternative. */
bindingset[regex]
private predicate hasCatchAllTopLevelAlternative(string regex) {
  exists(int start, int end |
    start >= 0 and end >= start and end <= regex.length() and
    (start = 0 or exists(int previous |
      isTopLevelRegexSeparator(regex, previous) and start = previous + 1
    )) and
    (end = regex.length() or isTopLevelRegexSeparator(regex, end)) and
    not exists(int separator |
      separator >= start and separator < end and isTopLevelRegexSeparator(regex, separator)
    ) and
    isCatchAllOriginRegex(regex.substring(start, end))
  )
}

/**
 * Holds if the CORS origin regular expression `regex` accepts origins that are
 * likely not intended, such as any origin, or attacker-registrable domains due to
 * unescaped dots, an unbounded wildcard directly preceding the domain name, or an
 * unbounded wildcard after the domain name.
 */
bindingset[regex]
predicate isPermissiveOriginRegex(string regex) {
  // The complete expression and each top-level alternative can match any origin.
  isCatchAllOriginRegex(regex) or
  hasCatchAllTopLevelAlternative(regex)
  or
  exists(string r |
    // Ignore the contents of character classes, e.g. the `.` in `[a-z.]`.
    r = regex.regexpReplaceAll("\\[(\\\\.|[^\\]\\\\])*\\]", "#")
  |
    // An unescaped `.` used as a domain separator, e.g. `restaurant.com`.
    r.regexpMatch("(.*[^\\\\])?\\.[a-zA-Z0-9].*")
    or
    // An unbounded wildcard directly followed by a domain name, e.g. `.*example\.com`.
    r.regexpMatch("(.*[^\\\\])?\\.[*+]\\??(?!\\((?:\\?:)?\\\\\\.)[a-zA-Z0-9(].*")
    or
    // An unbounded wildcard after the domain name, e.g. `example\.com.*`.
    r.regexpMatch(".*[^\\\\:]\\.[*+]\\??\\$?\\)?")
  )
}

/** Gets the value of the keyword argument `name` of the CORS middleware `mw`. */
DataFlow::Node corsMiddlewareArg(Http::Server::CorsMiddleware mw, string name) {
  result = mw.(DataFlow::CallCfgNode).getArgByName(name)
}

/** Holds if the CORS middleware `mw` allows credentialed requests. */
predicate corsAllowsCredentials(Http::Server::CorsMiddleware mw) {
  mw.getMiddlewareName() = "CORSMiddleware" and
  mw.getCredentialsAllowed().getALocalSource().asExpr() instanceof True
}

from DataFlow::Node node, string message
where
  exists(string value |
    headerWrite(node, "access-control-allow-origin", value) and
    (
      value.trim() = "*" and
      message =
        "The Access-Control-Allow-Origin header is set to '*', allowing any website to read this response."
      or
      value.trim() = "null" and
      message =
        "The Access-Control-Allow-Origin header is set to 'null', allowing sandboxed or opaque origins to read this response."
    )
  )
  or
  exists(string value |
    headerWrite(node, "content-security-policy", value) and
    cspAllowsInlineScript(value) and
    message =
      "This Content-Security-Policy allows inline scripts via 'unsafe-inline', which negates its protection against script injection."
  )
  or
  exists(Http::Server::CorsMiddleware mw | corsAllowsCredentials(mw) |
    exists(string regex |
      node = corsMiddlewareArg(mw, "allow_origin_regex") and
      regex = constantString(node) and
      isPermissiveOriginRegex(regex) and
      message =
        "This CORS middleware allows credentialed requests from origins matching the overly permissive regular expression '"
          + regex + "'."
    )
    or
    node = corsMiddlewareArg(mw, "allow_origins") and
    exists(Expr origins | origins = node.getALocalSource().asExpr() |
      (origins instanceof List or origins instanceof Tuple) and
      origins.getASubExpression().(StringLiteral).getText() = "*"
    ) and
    message = "This CORS middleware allows credentialed requests from any origin."
  )
select node, message
