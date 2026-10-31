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

/** Gets a directive (trimmed, lower-cased) of the Content-Security-Policy value `csp`. */
bindingset[csp]
string cspDirective(string csp) { result = csp.splitAt(";").trim().toLowerCase() and result != "" }

/** Gets the name of the CSP directive `directive`. */
bindingset[directive]
string cspDirectiveName(string directive) { result = directive.regexpCapture("([a-z-]+).*", 1) }

/**
 * Holds if the CSP `directive` allows inline scripts, that is, it contains
 * `'unsafe-inline'` and no nonce or hash source (which would make browsers ignore it).
 */
bindingset[directive]
predicate directiveAllowsInlineScript(string directive) {
  directive.matches("%'unsafe-inline'%") and
  not directive.regexpMatch(".*'(nonce|sha256|sha384|sha512)-.*")
}

/** Holds if the Content-Security-Policy value `csp` allows inline scripts. */
bindingset[csp]
predicate cspAllowsInlineScript(string csp) {
  exists(string directive | directive = cspDirective(csp) |
    cspDirectiveName(directive) = ["script-src", "script-src-elem", "script-src-attr"] and
    directiveAllowsInlineScript(directive)
    or
    // `default-src` only applies to scripts when no `script-src` directive is present.
    cspDirectiveName(directive) = "default-src" and
    directiveAllowsInlineScript(directive) and
    not cspDirectiveName(cspDirective(csp)) = "script-src"
  )
}

/**
 * Holds if the CORS origin regular expression `regex` accepts origins that are
 * likely not intended, such as any origin, or attacker-registrable domains due to
 * unescaped dots or an unbounded wildcard directly preceding the domain name.
 */
bindingset[regex]
predicate isPermissiveOriginRegex(string regex) {
  // Matches any origin, e.g. `.*` or `^.+$`.
  regex.regexpMatch("\\^?\\.[*+]\\$?")
  or
  // An unescaped `.` used as a domain separator, e.g. `restaurant.com`.
  regex.regexpMatch("(.*[^\\\\])?\\.[a-zA-Z0-9].*")
  or
  // An unbounded wildcard directly followed by a domain name, e.g. `.*example\.com`.
  regex.regexpMatch("(.*[^\\\\])?\\.[*+]\\??[a-zA-Z0-9(].*")
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
    value.trim() = ["*", "null"] and
    message =
      "The Access-Control-Allow-Origin header is set to '" + value.trim() +
        "', allowing any website to read this response."
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
