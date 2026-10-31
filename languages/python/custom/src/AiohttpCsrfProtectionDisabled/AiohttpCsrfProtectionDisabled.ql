/**
 * @name aiohttp session middleware without CSRF middleware
 * @description An aiohttp application that enables cookie-backed sessions without
 *              adding CSRF middleware may accept cross-site state-changing requests.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision medium
 * @id py/custom/aiohttp-csrf-protection-disabled
 * @tags security
 *       external/cwe/cwe-352
 */

import python
import semmle.python.ApiGraphs

private predicate configuresSessionWithoutCsrf(API::CallNode app) {
  exists(List middlewares, Name middleware |
    middlewares = app.getArgByName("middlewares").asExpr() and
    middleware = middlewares.getAnElt() and
    middleware.getId().toLowerCase().matches("%session%") and
    not exists(Name csrfMiddleware |
      csrfMiddleware = middlewares.getAnElt() and
      csrfMiddleware.getId().toLowerCase().matches("%csrf%")
    )
  )
}

private predicate hasUnsafeRoute() {
  exists(Call route, Attribute addRoute, Attribute router, StringLiteral method |
    route.getFunc() = addRoute and
    addRoute.getName() = "add_route" and
    router = addRoute.getObject() and
    router.getName() = "router" and
    method = route.getArg(0) and
    method.getText().toUpperCase() in ["POST", "PUT", "PATCH", "DELETE"]
  )
}

from API::CallNode app
where
  app = API::moduleImport("aiohttp").getMember("web").getMember("Application").getACall() and
  configuresSessionWithoutCsrf(app) and
  hasUnsafeRoute()
select app,
  "This aiohttp application enables session middleware without adding CSRF middleware and registers an unsafe route."
