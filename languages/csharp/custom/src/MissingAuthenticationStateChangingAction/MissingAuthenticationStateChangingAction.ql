/**
 * @name State-changing action reachable without authentication
 * @description An MVC or Web API action that changes server state (for example by handling a
 *              `POST`, `PUT`, `PATCH` or `DELETE` request) and is not protected by any
 *              authorization attribute, global authorization policy or check of the current
 *              user can be invoked by anonymous remote clients. This also covers actions where
 *              `[AllowAnonymous]` overrides a controller-level `[Authorize]`.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id cs/web/missing-authentication-state-changing-action
 * @tags security
 *       external/cwe/cwe-284
 *       external/cwe/cwe-306
 *       external/cwe/cwe-862
 */

import csharp
import semmle.code.csharp.frameworks.microsoft.AspNetCore
import AccessControl.AccessControlCoverage
private import semmle.code.csharp.security.auth.MissingFunctionLevelAccessControlQuery as MissingAccessControl

/**
 * Holds if `m` has no authorization requirement: no applicable authorization or
 * `[AllowAnonymous]` attribute, no `Web.config` `<deny>` rule and no global policy.
 */
predicate hasNoAuthorization(ActionMethod m) {
  not isAuthorizationAttribute(getAnApplicableAttribute(m)) and
  not isAllowAnonymousAttribute(getAnApplicableAttribute(m)) and
  not MissingAccessControl::hasAuthViaXml(m) and
  not hasGlobalAuthorizationPolicy()
}

/**
 * Holds if `[AllowAnonymous]` on `m` overrides an authorization attribute that applies to its
 * controller, and `m` acts on an existing resource selected by ID.
 */
predicate allowAnonymousOverridesAuthorize(ActionMethod m) {
  isAllowAnonymousAttribute(m.getOverridee*().getAnAttribute()) and
  isAuthorizationAttribute(getAnApplicableAttribute(m)) and
  isStateChanging(m) and
  hasIdParameter(m)
}

from ActionMethod m, string msg
where
  m = any(MicrosoftAspNetCoreMvcController c).getAnActionMethod() and
  (hasMutatingHttpVerb(m) or isStateChanging(m)) and
  not isAuthenticationFlow(m) and
  not checksCurrentUser(m) and
  exists(m.getBody().getAChildStmt()) and
  (
    hasNoAuthorization(m) and
    // Already reported by `cs/web/missing-function-level-access-control`.
    not MissingAccessControl::missingAuth(m) and
    msg = "This state-changing action can be invoked without authentication."
    or
    allowAnonymousOverridesAuthorize(m) and
    msg =
      "This state-changing action is marked [AllowAnonymous], which overrides the authorization required by its controller."
  )
select m, msg
