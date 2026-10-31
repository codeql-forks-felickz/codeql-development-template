/**
 * @name Logout action lacks CSRF protection
 * @description A logout action that signs out the current user without anti-forgery protection
 *              can be invoked cross-site, potentially disrupting the user's session.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id cs/web/missing-logout-csrf-protection
 * @tags security
 *       external/cwe/cwe-352
 */

import csharp
import semmle.code.csharp.frameworks.microsoft.AspNetCore
import semmle.code.csharp.security.auth.ActionMethods
import AccessControl.AccessControlCoverage

private class LogoutAction extends ActionMethod {
  LogoutAction() {
    this = any(MicrosoftAspNetCoreMvcController controller).getAnActionMethod() and
    this.getName()
        .regexpReplaceAll("([a-z])([A-Z])", "$1_$2")
        .toLowerCase()
        .regexpMatch(".*(log_?out|sign_?out).*")
  }
}

private predicate callsSignOut(ActionMethod action) {
  exists(Callable c, MethodCall signOut |
    action.calls*(c) and
    c = signOut.getEnclosingCallable() and
    signOut.getTarget().getName() in ["SignOut", "SignOutAsync"] and
    signOut
        .getTarget()
        .getDeclaringType()
        .getName()
        .regexpMatch(".*(Authentication|SignInManager).*")
  )
}

private predicate hasPostRestriction(ActionMethod action) {
  getAnApplicableAttribute(action)
      .getType()
      .hasFullyQualifiedName("Microsoft.AspNetCore.Mvc", "HttpPostAttribute")
}

private predicate hasValidateAntiForgeryAttribute(ActionMethod action) {
  exists(Attribute attribute |
    attribute = getAnApplicableAttribute(action) and
    attribute instanceof ValidateAntiForgeryAttribute and
    not attribute.getType().getName().matches("Auto%")
  )
}

private predicate hasManualAntiForgeryValidation(ActionMethod action) {
  exists(Callable c, MethodCall validation |
    action.calls*(c) and
    c = validation.getEnclosingCallable() and
    validation.getTarget().getName() in ["Validate", "ValidateRequestAsync"] and
    validation
        .getTarget()
        .getDeclaringType()
        .getName()
        .regexpMatch(".*(AntiForgery|IAntiforgery).*")
  )
}

private predicate hasAutoValidateAntiForgeryAttribute(ActionMethod action) {
  exists(Attribute attribute |
    attribute = getAnApplicableAttribute(action) and
    attribute instanceof ValidateAntiForgeryAttribute and
    attribute.getType().getName().matches("Auto%")
  )
}

from LogoutAction action
where
  callsSignOut(action) and
  not (
    hasValidateAntiForgeryAttribute(action)
    or
    hasManualAntiForgeryValidation(action)
    or
    hasPostRestriction(action) and hasAutoValidateAntiForgeryAttribute(action)
  )
select action, "This logout action lacks anti-forgery protection against cross-site requests."
