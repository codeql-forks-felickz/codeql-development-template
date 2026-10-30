/**
 * @name CORS policy allows credentials from any origin
 * @description A CORS policy that allows credentials while accepting any origin lets any
 *              website send authenticated cross-origin requests and read the responses.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id cs/web/cors-credentials-any-origin
 * @tags security
 *       external/cwe/cwe-942
 */

import csharp

/** A call to a method of `Microsoft.AspNetCore.Cors.Infrastructure.CorsPolicyBuilder`. */
class CorsPolicyBuilderCall extends MethodCall {
  CorsPolicyBuilderCall() {
    this.getTarget()
        .getDeclaringType()
        .hasFullyQualifiedName("Microsoft.AspNetCore.Cors.Infrastructure", "CorsPolicyBuilder")
  }
}

/**
 * Gets the expression at the start of the fluent chain containing `c`, for example
 * `builder` in `builder.AllowAnyOrigin().AllowCredentials()`.
 */
Expr getChainRoot(CorsPolicyBuilderCall c) {
  result = c.getQualifier() and not result instanceof CorsPolicyBuilderCall
  or
  result = getChainRoot(c.getQualifier())
}

/** Holds if `c1` and `c2` configure the same `CorsPolicyBuilder`. */
predicate sameBuilder(CorsPolicyBuilderCall c1, CorsPolicyBuilderCall c2) {
  exists(Expr r1, Expr r2 | r1 = getChainRoot(c1) and r2 = getChainRoot(c2) |
    r1 = r2
    or
    c1.getEnclosingCallable() = c2.getEnclosingCallable() and
    (
      DataFlow::localExprFlow(r1, r2)
      or
      DataFlow::localExprFlow(r2, r1)
    )
    or
    exists(LocalVariable v, LocalVariableDeclAndInitExpr initialization |
      c1.getEnclosingCallable() = c2.getEnclosingCallable() and
      (
        r1 = v.getAnAccess() and
        initialization.getVariable() = v and
        (r2 = initialization.getInitializer() or r2.getParent*() = initialization.getInitializer())
        or
        r2 = v.getAnAccess() and
        initialization.getVariable() = v and
        (r1 = initialization.getInitializer() or r1.getParent*() = initialization.getInitializer())
      ) and
      not exists(Assignment reassignment |
        reassignment.getTargetVariable() = v and
        not reassignment instanceof LocalVariableDeclAndInitExpr
      )
    )
  )
}

/** Holds if `c` is inside a conditional branch. */
private predicate isConditionalOverride(CorsPolicyBuilderCall c) {
  exists(IfStmt branch |
    c.getEnclosingStmt().getParent*() = branch.getThen()
    or
    c.getEnclosingStmt().getParent*() = branch.getElse()
  )
}

/** Holds if `later` is called after `earlier` in the same fluent chain or unconditionally later. */
private predicate callComesAfter(CorsPolicyBuilderCall earlier, CorsPolicyBuilderCall later) {
  earlier.getEnclosingCallable() = later.getEnclosingCallable() and
  (
    exists(CorsPolicyBuilderCall qualifier |
      qualifier = later.getQualifier() and
      (qualifier = earlier or callComesAfter(earlier, qualifier))
    )
    or
    later.getControlFlowNode().postDominates(earlier.getControlFlowNode())
  )
}

/**
 * Holds if `override` runs before every explicit build that follows `configured`.
 * If the framework builds the policy after a configuration callback, the absence of an
 * explicit Build call means the callback's normal exit is the construction point.
 */
private predicate precedesPolicyConstruction(
  CorsPolicyBuilderCall configured, CorsPolicyBuilderCall override
) {
  not exists(CorsPolicyBuilderCall build |
    build.getTarget().hasName("Build") and
    sameBuilder(configured, build) and
    callComesAfter(configured, build) and
    not callComesAfter(override, build)
  )
}

/** Holds if `c` makes the policy accept every origin. */
predicate allowsAnyOrigin(CorsPolicyBuilderCall c) {
  c.getTarget().hasName("AllowAnyOrigin")
  or
  c.getTarget().hasName("SetIsOriginAllowed") and
  exists(LambdaExpr l | l = c.getArgument(0) |
    forex(Expr r | l.canReturn(r) | r.(BoolLiteral).getBoolValue() = true)
  )
}

/** Holds if `c` replaces an any-origin setting with a known restrictive setting. */
private predicate restrictsOrigins(CorsPolicyBuilderCall c) {
  c.getTarget().hasName("WithOrigins")
  or
  c.getTarget().hasName("SetIsOriginAllowed") and
  exists(LambdaExpr l, EqualityOperation eq, StringLiteral origin |
    l = c.getArgument(0) and
    l.canReturn(eq) and
    eq.getOperator() = "==" and
    origin = eq.getAnOperand()
  )
}

from CorsPolicyBuilderCall credentials, CorsPolicyBuilderCall anyOrigin
where
  credentials.getTarget().hasName("AllowCredentials") and
  allowsAnyOrigin(anyOrigin) and
  sameBuilder(credentials, anyOrigin) and
  not exists(CorsPolicyBuilderCall override |
    override.getTarget().hasName("DisallowCredentials") and
    sameBuilder(credentials, override) and
    not isConditionalOverride(override) and
    callComesAfter(credentials, override) and
    precedesPolicyConstruction(credentials, override)
  ) and
  not exists(CorsPolicyBuilderCall override |
    restrictsOrigins(override) and
    sameBuilder(anyOrigin, override) and
    not isConditionalOverride(override) and
    callComesAfter(anyOrigin, override) and
    precedesPolicyConstruction(anyOrigin, override)
  )
select credentials, "This CORS policy allows credentials for $@.", anyOrigin, "any origin"
