/**
 * Provides shared definitions for C# access-control queries that extend the coverage of
 * `cs/web/insecure-direct-object-reference` and `cs/web/missing-function-level-access-control`.
 *
 * This library:
 * - models public WCF service operations (`[OperationContract]`) as web endpoints (`ActionMethod`),
 * - provides a broader notion of a state-changing action than `ActionMethod.isEdit()`,
 * - provides a heuristic for whether an action inspects the identity, roles or claims of the
 *   current caller (an ownership or role check), and
 * - distinguishes a bare `[Authorize]` (authentication only) from one that restricts access
 *   by role or policy.
 */

import csharp
import semmle.code.csharp.security.auth.ActionMethods
private import semmle.code.csharp.security.auth.MissingFunctionLevelAccessControlQuery as MissingAccessControl

private predicate isServiceContract(ValueOrRefType t) {
  t.getAnAttribute()
      .getType()
      .hasFullyQualifiedName("System.ServiceModel", "ServiceContractAttribute")
}

private predicate isOperationContract(Method m) {
  m.getAnAttribute()
      .getType()
      .hasFullyQualifiedName("System.ServiceModel", "OperationContractAttribute") and
  isServiceContract(m.getDeclaringType())
}

/**
 * A WCF service operation, that is, a method marked with `[OperationContract]` on a
 * `[ServiceContract]` type, or a method implementing such an operation of a service contract
 * interface. These are remotely callable endpoints.
 */
class WcfServiceOperation extends ActionMethod {
  WcfServiceOperation() {
    this.fromSource() and
    exists(this.getBody()) and
    (
      isOperationContract(this)
      or
      isOperationContract(this.getAnUltimateImplementee())
    )
  }

  /** Gets the service contract declaration of this operation (itself, or the interface method it implements). */
  Method getAContractMethod() {
    result = this and isOperationContract(this)
    or
    result = this.getAnUltimateImplementee() and isOperationContract(result)
  }
}

/** Gets a lower-case version of `s`, with camelCase words separated by `_`. */
bindingset[s]
private string splitWords(string s) {
  result = s.regexpReplaceAll("([a-z0-9])([A-Z])", "$1_$2").toLowerCase()
}

/**
 * Holds if `m` may perform a stateful action, such as editing, updating or deleting a resource.
 *
 * This extends `ActionMethod.isEdit()` with additional verbs (such as `update` and `remove`) and
 * with the ASP.NET `[HttpPut]`, `[HttpPatch]` and `[HttpDelete]` attributes.
 */
predicate isStateChanging(ActionMethod m) {
  m.isEdit()
  or
  splitWords(m.getName())
      .regexpMatch("(.*_)?(update|delete|remove|edit|modify|change|set|save|cancel)(_.*)?")
  or
  m.getOverridee*()
      .getAnAttribute()
      .getType()
      .hasFullyQualifiedName(["Microsoft.AspNetCore.Mvc", "System.Web.Mvc", "System.Web.Http"],
        ["HttpPutAttribute", "HttpPatchAttribute", "HttpDeleteAttribute"])
}

/** Holds if the name of parameter `p` indicates that it identifies a resource, such as `id` or `orderId`. */
private predicate isIdParameter(Parameter p) {
  p.getName().regexpMatch("(?i)(id|idx)")
  or
  p.getName().regexpMatch(".*[a-z0-9](Id|ID|Idx)")
  or
  p.getName().regexpMatch("(?i).*_(id|idx)")
}

/** Holds if `m` has a parameter that identifies the resource being acted upon. */
predicate hasIdParameter(ActionMethod m) { isIdParameter(m.getAParameter()) }

/**
 * An expression that inspects the identity, roles or claims of the current caller, or that
 * performs an explicit authorization check.
 */
class CurrentUserCheck extends Expr {
  CurrentUserCheck() {
    this instanceof MissingAccessControl::AuthExpr
    or
    this.getType()
        .(ValueOrRefType)
        .getABaseType*()
        .hasFullyQualifiedName("System.Security.Principal", ["IPrincipal", "IIdentity"])
    or
    this.getType()
        .(ValueOrRefType)
        .hasFullyQualifiedName("System.ServiceModel", ["ServiceSecurityContext", "OperationContext"])
    or
    this.(Call).getTarget().getDeclaringType().getName().regexpMatch("(?i).*auth.*")
    or
    this.(MemberAccess).getTarget().getDeclaringType().getName().regexpMatch("(?i).*auth.*")
  }
}

/** Gets the callable enclosing `e`, or a callable enclosing a lambda that encloses `e`. */
private Callable getAnEnclosingCallable(Expr e) {
  result = e.getEnclosingCallable()
  or
  result = getAnEnclosingCallable(e.getEnclosingCallable().(AnonymousFunctionExpr))
}

/**
 * Holds if `m`, or a source callable it (transitively) calls, inspects the current caller or
 * performs an explicit authorization check.
 */
predicate checksCurrentUser(ActionMethod m) {
  exists(Callable c, CurrentUserCheck check |
    m.getAnAuthorizingCallable().calls*(c) and
    c = getAnEnclosingCallable(check)
  )
}

private ValueOrRefType getAnUnboundBaseType(ValueOrRefType t) {
  result = t.getABaseType().getUnboundDeclaration()
}

/**
 * Gets an attribute that applies to `m`: directly, via an overridden method, via its
 * declaring type (or a base type), or via the WCF service contract it implements.
 */
Attribute getAnApplicableAttribute(ActionMethod m) {
  result = m.getOverridee*().getAnAttribute()
  or
  result = getAnUnboundBaseType*(m.getDeclaringType()).getAnAttribute()
  or
  result = m.(WcfServiceOperation).getAContractMethod().getAnAttribute()
  or
  result = m.(WcfServiceOperation).getAContractMethod().getDeclaringType().getAnAttribute()
}

private predicate isAuthorizeAttributeType(Class c) {
  c.hasFullyQualifiedName([
      "Microsoft.AspNetCore.Authorization", "System.Web.Mvc", "System.Web.Http"
    ], "AuthorizeAttribute")
}

private predicate isAllowAnonymousAttributeType(Class c) {
  c.hasFullyQualifiedName([
      "Microsoft.AspNetCore.Authorization", "System.Web.Mvc", "System.Web.Http"
    ], "AllowAnonymousAttribute")
}

/**
 * Holds if `a` is a plain `[Authorize]` attribute that only requires the caller to be
 * authenticated, that is, it specifies no roles, users or policy.
 */
private predicate isAuthenticationOnlyAttribute(Attribute a) {
  isAuthorizeAttributeType(a.getType()) and
  not exists(a.getConstructorArgument(_)) and
  not exists(a.getNamedArgument(["Roles", "Users", "Policy"]))
}

/**
 * Holds if `a` is an attribute that may restrict access beyond authentication, such as an
 * `[Authorize]` with roles or a policy, a custom authorization attribute, or a
 * `[PrincipalPermission]` demand.
 */
predicate isRestrictingAuthorizationAttribute(Attribute a) {
  not isAuthenticationOnlyAttribute(a) and
  not isAllowAnonymousAttributeType(a.getType()) and
  a.getType().getABaseType*().getName().regexpMatch("(?i).*(auth|permission|principal|role).*")
}

/**
 * Holds if `m` requires an authenticated caller only through a plain `[Authorize]` attribute,
 * and is not otherwise restricted by role, policy or a custom authorization attribute.
 */
predicate isProtectedOnlyByAuthentication(ActionMethod m) {
  isAuthenticationOnlyAttribute(getAnApplicableAttribute(m)) and
  not isRestrictingAuthorizationAttribute(getAnApplicableAttribute(m)) and
  not isAllowAnonymousAttributeType(getAnApplicableAttribute(m).getType())
}

/** Holds if `a` is an `[AllowAnonymous]` attribute. */
predicate isAllowAnonymousAttribute(Attribute a) { isAllowAnonymousAttributeType(a.getType()) }

/**
 * Holds if `a` is an attribute that may require authentication or authorization, such as
 * `[Authorize]`, a custom authorization attribute or a `[PrincipalPermission]` demand.
 */
predicate isAuthorizationAttribute(Attribute a) {
  not isAllowAnonymousAttribute(a) and
  a.getType().getABaseType*().getName().regexpMatch("(?i).*(auth|permission|principal|role).*")
}

/**
 * Holds if `m` has an HTTP method attribute for a verb that is expected to change server
 * state (`POST`, `PUT`, `PATCH` or `DELETE`).
 */
predicate hasMutatingHttpVerb(ActionMethod m) {
  m.getOverridee*()
      .getAnAttribute()
      .getType()
      .hasFullyQualifiedName(["Microsoft.AspNetCore.Mvc", "System.Web.Mvc", "System.Web.Http"],
        ["HttpPostAttribute", "HttpPutAttribute", "HttpPatchAttribute", "HttpDeleteAttribute"])
}

/**
 * Holds if the name of `m` indicates that it is part of an authentication flow, such as
 * logging in or registering, which is expected to be reachable anonymously.
 */
predicate isAuthenticationFlow(ActionMethod m) {
  splitWords(m.getName())
      .regexpMatch("(.*_)?(log_?in|log_?on|log_?out|log_?off|sign_?in|sign_?up|sign_?out|register|token|authenticate|forgot|reset|confirm|verify|challenge|callback|error)(_.*)?")
}

/**
 * Holds if the application configures authorization globally, for example by registering an
 * `AuthorizeFilter` or a global `[Authorize]` filter, calling `RequireAuthorization()` on the
 * endpoints, or setting an authorization `FallbackPolicy`.
 */
predicate hasGlobalAuthorizationPolicy() {
  exists(ObjectCreation oc | oc.fromSource() |
    oc.getObjectType().hasName("AuthorizeFilter")
    or
    isAuthorizeAttributeType(oc.getObjectType())
  )
  or
  exists(MethodCall mc | mc.fromSource() | mc.getTarget().hasName("RequireAuthorization"))
  or
  exists(AssignableDefinition def |
    def.getTarget().(Property).hasName(["FallbackPolicy", "DefaultPolicy"]) and
    def.getExpr().fromSource()
  )
}
