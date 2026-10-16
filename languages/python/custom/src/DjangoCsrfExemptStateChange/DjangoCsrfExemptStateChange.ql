/**
 * @name CSRF protection disabled on state-changing Django view
 * @description A Django view decorated with `@csrf_exempt` that changes server-side
 *              state (for example saving a model or changing a password) can be
 *              triggered by a cross-site request carrying the victim's session cookie.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision high
 * @id py/custom/django-csrf-exempt-state-change
 * @tags security
 *       external/cwe/cwe-352
 */

import python
import semmle.python.Concepts
import DjangoStateChange

from Http::Server::CsrfLocalProtectionSetting exempt, Function view, string operations
where
  not exempt.csrfEnabled() and
  view = exempt.getRequestHandler() and
  operations =
    strictconcat(string op |
      exists(DjangoStateChangingCall call |
        performsStateChange(view, call) and op = call.getOperation()
      )
    |
      "'" + op + "'", ", "
    ) and
  not usesNonCookieAuthentication(view) and
  // Ignore test code, as in `py/csrf-protection-disabled`.
  not view.getLocation().getFile().getRelativePath().matches("%test%")
select exempt,
  "CSRF protection is disabled for $@, which performs state-changing operations (" + operations +
    ").", view, view.getName()
