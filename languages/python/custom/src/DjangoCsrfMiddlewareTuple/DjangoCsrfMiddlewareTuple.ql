/**
 * @name CSRF protection disabled in Django tuple middleware setting
 * @description Disabling CSRF protection in a Django `MIDDLEWARE` setting written as a
 *              tuple makes the application vulnerable to Cross-Site Request Forgery attacks.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision high
 * @id py/custom/csrf-protection-disabled-tuple
 * @tags security
 *       external/cwe/cwe-352
 */

import python
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow

/**
 * A Django `MIDDLEWARE` setting written as a tuple. The standard library only models
 * the list form (`DjangoSettingsMiddlewareStack`), so a tuple without
 * `CsrfViewMiddleware` is not reported by `py/csrf-protection-disabled`.
 */
class DjangoSettingsMiddlewareTuple extends Http::Server::CsrfProtectionSetting::Range {
  Tuple tuple;

  DjangoSettingsMiddlewareTuple() {
    this.asExpr() = tuple and
    exists(DataFlow::Node mw |
      mw.asExpr().(Name).getId() = "MIDDLEWARE" and
      DataFlow::localFlow(this, mw)
    |
      // As in the standard library, CSRF protection only matters when the Django
      // authentication middleware (session cookie based auth) is enabled.
      tuple.getAnElt().(StringLiteral).getText() =
        "django.contrib.auth.middleware.AuthenticationMiddleware"
    )
  }

  override boolean getVerificationSetting() {
    if
      tuple.getAnElt().(StringLiteral).getText() in [
          "django.middleware.csrf.CsrfViewMiddleware",
          // see https://github.com/mozilla/django-session-csrf
          "session_csrf.CsrfMiddleware"
        ]
    then result = true
    else result = false
  }
}

predicate relevantSetting(Http::Server::CsrfProtectionSetting s) {
  // rule out test code as this is a common place to turn off CSRF protection.
  // The path is relative to the source root, so a checkout location that happens
  // to contain `test` does not suppress all results.
  not s.getLocation().getFile().getRelativePath().matches("%test%")
}

predicate vulnerableSetting(Http::Server::CsrfProtectionSetting s) {
  s.getVerificationSetting() = false and
  not exists(Http::Server::CsrfLocalProtectionSetting p | p.csrfEnabled()) and
  relevantSetting(s)
}

from DjangoSettingsMiddlewareTuple setting
where
  vulnerableSetting(setting) and
  // As in `py/csrf-protection-disabled`, require all non-test settings (list or tuple)
  // to be vulnerable, to rule out dummy projects next to a protected main project.
  forall(Http::Server::CsrfProtectionSetting s | relevantSetting(s) | vulnerableSetting(s))
select setting, "Potential CSRF vulnerability due to forgery protection being disabled or weakened."
