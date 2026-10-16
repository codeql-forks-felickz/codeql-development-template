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
    exists(LocalScopeVariable v |
      r1 = v.getAnAccess() and
      r2 = v.getAnAccess() and
      c1.getEnclosingCallable() = c2.getEnclosingCallable()
    )
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

from CorsPolicyBuilderCall credentials, CorsPolicyBuilderCall anyOrigin
where
  credentials.getTarget().hasName("AllowCredentials") and
  allowsAnyOrigin(anyOrigin) and
  sameBuilder(credentials, anyOrigin)
select credentials, "This CORS policy allows credentials for $@.", anyOrigin, "any origin"
