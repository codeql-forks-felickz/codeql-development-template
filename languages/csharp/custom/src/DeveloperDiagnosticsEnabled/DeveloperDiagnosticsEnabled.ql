/**
 * @name Developer diagnostics exposed to remote users
 * @description Enabling the ASP.NET Core developer exception page outside of a development
 *              environment check, or enabling ASP.NET page tracing at runtime, exposes stack
 *              traces, source paths, request data and server details to remote users.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.4
 * @precision high
 * @id cs/developer-diagnostics-enabled
 * @tags security
 *       external/cwe/cwe-209
 *       external/cwe/cwe-489
 */

import csharp
import semmle.code.csharp.controlflow.Guards

/** Holds if `name` is a constant hosting environment name other than a production one. */
bindingset[name]
predicate isNonProductionEnvironmentName(string name) {
  not name.toLowerCase() = ["production", "staging"]
}

/**
 * Holds if `g` evaluating to `v` implies that the application runs in a non-production hosting
 * environment, for example `env.IsDevelopment()` being `true` or `env.IsProduction()` being
 * `false`.
 */
predicate isNonProductionEnvironmentGuard(Guard g, boolean v) {
  exists(MethodCall mc | mc = g |
    mc.getTarget().hasName("IsDevelopment") and v = true
    or
    mc.getTarget().hasName(["IsProduction", "IsStaging"]) and v = false
    or
    mc.getTarget().hasName("IsEnvironment") and
    exists(string name | name = mc.getArgument(mc.getNumberOfArguments() - 1).getValue() |
      isNonProductionEnvironmentName(name) and v = true
      or
      not isNonProductionEnvironmentName(name) and v = false
    )
  )
  or
  exists(EqualityOperation eq, PropertyAccess pa, string name |
    eq = g and
    pa = eq.getAnOperand() and
    pa.getTarget().hasName("EnvironmentName") and
    name = eq.getAnOperand().getValue()
  |
    eq instanceof EQExpr and
    (
      isNonProductionEnvironmentName(name) and v = true
      or
      not isNonProductionEnvironmentName(name) and v = false
    )
    or
    eq instanceof NEExpr and
    (
      isNonProductionEnvironmentName(name) and v = false
      or
      not isNonProductionEnvironmentName(name) and v = true
    )
  )
}

/** Holds if `e` is only evaluated in a non-production hosting environment. */
predicate isNonProductionOnly(Expr e) {
  exists(Guard g, GuardValue v |
    isNonProductionEnvironmentGuard(g, v.asBooleanValue()) and
    g.controlsNode(e.getControlFlowNode(), v)
  )
  or
  // Environment-specific startup conventions, which ASP.NET Core only invokes in the
  // `Development` environment.
  e.getEnclosingCallable().getName().toLowerCase() = "configuredevelopment"
  or
  e.getEnclosingCallable().getDeclaringType().getName().toLowerCase() = "startupdevelopment"
}

/** Holds if `e` is a check that the request comes from the local machine (`Request.IsLocal`). */
predicate isLocalRequestCheck(Expr e) { e.(PropertyAccess).getTarget().hasName("IsLocal") }

/** Holds if `e` is only evaluated for requests from the local machine. */
predicate isLocalRequestOnly(Expr e) {
  exists(Guard g, GuardValue v |
    isLocalRequestCheck(g) and
    v.asBooleanValue() = true and
    g.controlsNode(e.getControlFlowNode(), v)
  )
}

from Expr e, string msg
where
  exists(MethodCall mc | mc = e |
    mc.getTarget().hasName(["UseDeveloperExceptionPage", "UseDatabaseErrorPage"]) and
    mc.getTarget().getDeclaringType().getNamespace().getFullName() = "Microsoft.AspNetCore.Builder" and
    not isNonProductionOnly(mc) and
    msg =
      "'" + mc.getTarget().getName() +
        "' is enabled without checking the hosting environment, so detailed exception information is exposed to remote users in production."
  )
  or
  exists(AssignExpr a, Property p | a = e |
    a.getLeftOperand().(PropertyAccess).getTarget() = p and
    p.hasName("IsEnabled") and
    p.getDeclaringType().hasFullyQualifiedName("System.Web", "TraceContext") and
    not a.getRightOperand().getValue() = "false" and
    not isLocalRequestCheck(a.getRightOperand()) and
    not isLocalRequestOnly(a) and
    msg =
      "ASP.NET page tracing is enabled at runtime, exposing request headers, cookies, session state and server variables to remote users."
  )
select e, msg
