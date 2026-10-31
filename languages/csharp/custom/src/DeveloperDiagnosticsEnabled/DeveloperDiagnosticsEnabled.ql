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

/**
 * Gets the condition of an `if` statement or conditional expression that controls whether `e`
 * is evaluated, either by enclosing `e` or by exiting the callable early before `e`.
 */
Expr getAGuardingCondition(Expr e) {
  exists(IfStmt s | result = s.getCondition() |
    [s.getThen(), s.getElse()].getAChildStmt*() = e.getEnclosingStmt()
    or
    // An early exit, such as `if (!env.IsDevelopment()) return;`, before `e`.
    s.getEnclosingCallable() = e.getEnclosingCallable() and
    s.getThen().getAChildStmt*() instanceof JumpStmt and
    s.getLocation().getEndLine() < e.getLocation().getStartLine() and
    not s.getAChildStmt*() = e.getEnclosingStmt()
  )
  or
  exists(ConditionalExpr c | result = c.getCondition() |
    [c.getThen(), c.getElse()].getAChildExpr*() = e
  )
}

/** Holds if `cond` checks the hosting environment, for example `env.IsDevelopment()`. */
predicate isEnvironmentCheck(Expr cond) {
  exists(Expr sub | sub = cond.getAChildExpr*() |
    sub.(Call).getTarget().hasName(["IsDevelopment", "IsEnvironment", "IsStaging", "IsProduction"])
    or
    sub.(PropertyAccess).getTarget().hasName("EnvironmentName")
  )
}

/** Holds if `cond` checks that the request comes from the local machine (`Request.IsLocal`). */
predicate isLocalRequestCheck(Expr cond) {
  cond.getAChildExpr*().(PropertyAccess).getTarget().hasName("IsLocal")
}

from Expr e, string msg
where
  exists(MethodCall mc | mc = e |
    mc.getTarget().hasName(["UseDeveloperExceptionPage", "UseDatabaseErrorPage"]) and
    mc.getTarget().getDeclaringType().getNamespace().getFullName() = "Microsoft.AspNetCore.Builder" and
    not isEnvironmentCheck(getAGuardingCondition(mc)) and
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
    not isLocalRequestCheck(getAGuardingCondition(a)) and
    msg =
      "ASP.NET page tracing is enabled at runtime, exposing request headers, cookies, session state and server variables to remote users."
  )
select e, msg
