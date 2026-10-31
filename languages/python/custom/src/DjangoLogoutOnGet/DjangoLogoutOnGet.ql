/**
 * @name Django logout view exposed to GET requests
 * @description Routing Django's `logout_then_login` view directly allows a cross-site
 *              GET request to log out an authenticated user.
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 3.1
 * @precision high
 * @id py/custom/django-logout-on-get
 * @tags security
 *       external/cwe/cwe-352
 */

import python
import semmle.python.ApiGraphs
import semmle.python.frameworks.Django

from PrivateDjango::DjangoRouteSetup route, API::Node logout
where
  route.getViewArg() = logout.getAValueReachableFromSource() and
  logout =
    API::moduleImport("django")
        .getMember("contrib")
        .getMember("auth")
        .getMember("views")
        .getMember("logout_then_login") and
  not route.getLocation().getFile().getRelativePath().matches("%test%")
select route, "This route exposes Django's logout_then_login view to cross-site GET requests."
