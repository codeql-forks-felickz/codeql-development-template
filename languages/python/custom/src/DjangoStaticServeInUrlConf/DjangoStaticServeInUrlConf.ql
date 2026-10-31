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

/** Holds if `e` is a reference to a `DEBUG` setting, such as `settings.DEBUG` or `DEBUG`. */
predicate isDebugSetting(Expr e) {
  e.(Attribute).getName() = "DEBUG"
  or
  e.(Name).getId() = "DEBUG"
}

/** Holds if `call` only runs when the `DEBUG` setting is enabled. */
predicate inDebugGuard(API::CallNode call) {
  exists(If i |
    isDebugSetting(i.getTest()) and
    i.getBody().getAnItem().contains(call.asExpr())
  )
}

from API::CallNode route
where
  route = urlRoute() and
  route.getParameter(1, "view").asSink() = staticServe().getAValueReachableFromSource() and
  not inDebugGuard(route)
select route,
  "This URL pattern routes requests to 'django.views.static.serve', which is not suitable for production and serves files without access control."
