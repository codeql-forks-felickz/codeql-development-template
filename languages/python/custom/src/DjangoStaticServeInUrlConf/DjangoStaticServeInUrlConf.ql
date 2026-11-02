/**
 * @name Django static file view routed in URL configuration
 * @description Routing `django.views.static.serve` from a URLconf outside a `DEBUG` guard
 *              publicly exposes every file under the document root without authentication.
 *              Django documents this view as insecure and unsuitable for production.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id py/django-static-serve-in-urlconf
 * @tags security
 *       external/cwe/cwe-552
 */

import python
import semmle.python.ApiGraphs

/** Gets a reference to `django.views.static.serve`. */
API::Node staticServe() {
  result = API::moduleImport("django").getMember("views").getMember("static").getMember("serve")
}

/** Gets a call to a Django URL routing function (`path`, `re_path` or the legacy `url`). */
API::CallNode urlRoute() {
  result = API::moduleImport("django").getMember("urls").getMember(["path", "re_path"]).getACall()
  or
  result =
    API::moduleImport("django").getMember("conf").getMember("urls").getMember("url").getACall()
}

/** Holds if `e` refers to `django.conf.settings.DEBUG`, including aliases. */
predicate isDebugSetting(Expr e) {
  (e instanceof Attribute or e instanceof Name) and
  e =
    API::moduleImport("django")
        .getMember("conf")
        .getMember("settings")
        .getMember("DEBUG")
        .getAValueReachableFromSource()
        .asExpr()
}

/** Holds if a true value for `e` implies that Django's DEBUG setting is enabled. */
predicate isDebugEnabledCondition(Expr e) {
  isDebugSetting(e)
  or
  exists(BoolExpr condition |
    condition = e and
    condition.getOp() instanceof And and
    isDebugSetting(condition.getAValue())
  )
}

/** Holds if `call` only runs when the `DEBUG` setting is enabled. */
predicate inDebugGuard(API::CallNode call) {
  exists(If i |
    isDebugEnabledCondition(i.getTest()) and
    i.getBody().getAnItem().contains(call.asExpr())
  )
  or
  exists(If i, UnaryExpr test |
    test = i.getTest() and
    test.getOp() instanceof Not and
    isDebugSetting(test.getOperand()) and
    i.getOrelse().getAnItem().contains(call.asExpr())
  )
}

from API::CallNode route
where
  route = urlRoute() and
  route.getParameter(1, "view").asSink() = staticServe().getAValueReachableFromSource() and
  not inDebugGuard(route)
select route,
  "This URL pattern routes requests to 'django.views.static.serve', which is not suitable for production and serves files without access control."
