/**
 * @name Flask cookie-authenticated route without CSRF protection
 * @description A Flask route that accepts an unsafe HTTP method and uses the
 *              cookie-backed session is vulnerable to cross-site request forgery
 *              when the application does not register Flask-WTF CSRF protection.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision medium
 * @id py/custom/flask-csrf-protection-disabled
 * @tags security
 *       external/cwe/cwe-352
 */

import python
import semmle.python.ApiGraphs
import semmle.python.frameworks.Flask

private predicate usesCookieSession(Function handler) {
  exists(Name session |
    session.getId() = "session" and
    session.getScope().getEnclosingScope*() = handler and
    session =
      API::moduleImport("flask").getMember("session").getAValueReachableFromSource().asExpr()
  )
  or
  exists(Name g, Attribute session |
    g.getScope().getEnclosingScope*() = handler and
    g = API::moduleImport("flask").getMember("g").getAValueReachableFromSource().asExpr() and
    session.getObject() = g and
    session.getName() = "session"
  )
}

private predicate acceptsUnsafeMethod(Flask::FlaskRouteSetup route) {
  exists(StringLiteral method, Expr methods |
    methods = route.(DataFlow::CallCfgNode).getArgByName("methods").asExpr() and
    (
      method = methods.(List).getAnElt()
      or
      method = methods.(Tuple).getAnElt()
    ) and
    method.getText().toUpperCase() in ["POST", "PUT", "PATCH", "DELETE"]
  )
}

private predicate flaskWtfCsrfProtectRegistered() {
  exists(API::CallNode protect |
    protect = API::moduleImport("flask_wtf").getMember("CSRFProtect").getACall()
    or
    protect = API::moduleImport("flask_wtf").getMember("csrf").getMember("CSRFProtect").getACall()
  )
}

from Flask::FlaskRouteSetup route, Function handler
where
  handler = route.getARequestHandler() and
  acceptsUnsafeMethod(route) and
  usesCookieSession(handler) and
  not flaskWtfCsrfProtectRegistered()
select route,
  "This route accepts an unsafe HTTP method and uses the cookie-backed session without registered CSRF protection."
