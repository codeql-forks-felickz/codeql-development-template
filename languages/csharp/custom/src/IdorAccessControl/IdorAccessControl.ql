/**
 * @name Insecure direct object reference without ownership check
 * @description Using a user-controlled identifier (request parameter, cookie or route value)
 *              to select a database record, without checking that the current user is
 *              allowed to access that record, allows an attacker to read or modify other
 *              users' data.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id cs/web/idor-access-control
 * @tags security
 *       external/cwe/cwe-566
 *       external/cwe/cwe-639
 */

import csharp
import semmle.code.csharp.security.dataflow.flowsources.FlowSources
import semmle.code.csharp.security.dataflow.SqlInjectionQuery as SqlInjection

/** Holds if `name` looks like the name of a record identifier, such as `id`, `userId` or `orderNumber`. */
bindingset[name]
predicate isIdentifierName(string name) {
  name.toLowerCase().regexpMatch(".*(id|ids|idx|number|num|account|accounts|acct)")
}

/** Gets the qualifier of the keyed lookup `c`, such as `Request.Params` in `Request.Params["id"]`. */
private Expr getKeyedLookupQualifier(Call c) {
  result = c.(IndexerCall).getQualifier()
  or
  c.(MethodCall).getTarget().hasName(["Get", "GetValues"]) and
  result = c.(MethodCall).getQualifier()
}

/**
 * A user-controlled value that names a record identifier: either a remote parameter with an
 * identifier-like name, or a keyed lookup such as `Request.Cookies["userId"]` or
 * `Request.Params.Get("id")` on remote input.
 */
class IdentifierSource extends DataFlow::Node {
  IdentifierSource() {
    exists(ActiveThreatModelSource src |
      isIdentifierName(src.asParameter().getName()) and
      this = src
      or
      exists(Call c |
        isIdentifierName(c.getArgument(0).getValue()) and
        TaintTracking::localTaint(src, DataFlow::exprNode(getKeyedLookupQualifier(c))) and
        this.asExpr() = c
      )
    )
  }
}

/** Holds if `t` is an ADO.NET style database type (in a `System.Data` or `Microsoft.Data` namespace). */
private predicate isDataType(ValueOrRefType t) {
  t.getNamespace().getFullName().regexpMatch("(System|Microsoft)\\.Data(\\..*)?")
}

/** Holds if `t` is a database command parameter type, such as `SqlParameter`. */
private predicate isDbParameterType(ValueOrRefType t) {
  t.getABaseType*().hasFullyQualifiedName("System.Data", "IDataParameter")
  or
  isDataType(t) and t.getName().matches("%Parameter")
}

/** A value that is used to select a database record. */
class RecordLookupSink extends DataFlow::Node {
  RecordLookupSink() {
    // SQL text
    this instanceof SqlInjection::Sink
    or
    exists(ObjectCreation oc, ValueOrRefType t |
      t = oc.getObjectType() and
      isDataType(t) and
      t.getName().regexpMatch(".*(Command|DataAdapter)") and
      oc.getTarget().getParameter(0).getType() instanceof StringType and
      this.asExpr() = oc.getArgument(0)
    )
    or
    // Values of SQL query parameters: `p.Value = x`, `new SqlParameter("@p", x)`,
    // `cmd.Parameters.AddWithValue("@p", x)`
    exists(AssignExpr ae, PropertyAccess pa |
      pa = ae.getLeftOperand() and
      pa.getTarget().hasName("Value") and
      isDbParameterType(pa.getTarget().getDeclaringType()) and
      this.asExpr() = ae.getRightOperand()
    )
    or
    exists(Call c |
      (
        isDbParameterType(c.(ObjectCreation).getObjectType())
        or
        c.getTarget().hasName("AddWithValue") and
        isDataType(c.getTarget().getDeclaringType())
      ) and
      c.getTarget().getParameter(1).getType() instanceof ObjectType and
      this.asExpr() = c.getArgument(1)
    )
    or
    // Entity Framework: `dbSet.Find(id)`
    exists(MethodCall mc, ValueOrRefType t |
      mc.getTarget().hasName(["Find", "FindAsync"]) and
      t = mc.getTarget().getDeclaringType().getUnboundDeclaration() and
      t.hasFullyQualifiedName(["Microsoft.EntityFrameworkCore", "System.Data.Entity"], "DbSet`1") and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // LINQ-to-database predicates: `dbSet.SingleOrDefault(x => x.Id == id)`
    exists(MethodCall mc, LambdaExpr lambda, EqualityOperation eq |
      mc.getTarget().getDeclaringType().hasFullyQualifiedName("System.Linq", "Queryable") and
      lambda = mc.getAnArgument() and
      eq.getEnclosingCallable() = lambda and
      this.asExpr() = eq.getAnOperand()
    )
  }
}

/** Holds if `t` represents the current principal or identity. */
private predicate isPrincipalType(ValueOrRefType t) {
  t.getABaseType*().hasFullyQualifiedName("System.Security.Principal", ["IPrincipal", "IIdentity"])
}

/**
 * Holds if `c` refers to the current user, for example via `User.Identity`, a
 * `UserManager`, `IAuthorizationService.AuthorizeAsync`, or a user-keyed session value.
 */
predicate referencesCurrentUser(Callable c) {
  exists(Expr e | e.getEnclosingCallable() = c |
    isPrincipalType(e.getType())
    or
    exists(Call call | call = e |
      call.getTarget().getDeclaringType().getUnboundDeclaration().getName() = "UserManager`1"
      or
      call.getTarget().hasName("AuthorizeAsync")
    )
    or
    exists(Call call | call = e |
      call.getTarget().getDeclaringType().getName() =
        ["HttpSessionState", "HttpSessionStateBase", "ISession"] and
      call.getArgument(0)
          .getValue()
          .toLowerCase()
          .regexpMatch(".*(user|customer|member|owner|account|principal).*")
    )
  )
}

/**
 * Holds if `c`, or its declaring type, is restricted to specific roles or policies,
 * for example `[Authorize(Roles = "Administrator")]`, or is an administrative handler.
 */
predicate isRoleRestricted(Callable c) {
  exists(Attribute attr |
    attr = c.(Attributable).getAnAttribute() or
    attr = c.getDeclaringType().getABaseType*().getAnAttribute()
  |
    attr.getType().getName() = "AuthorizeAttribute" and
    (exists(attr.getNamedArgument(["Roles", "Policy"])) or exists(attr.getArgument(0)))
  )
  or
  c.getName().toLowerCase().matches("%admin%")
  or
  c.getDeclaringType().getName().toLowerCase().matches("%admin%")
}

module IdorAccessControlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof IdentifierSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof RecordLookupSink }

  predicate isBarrier(DataFlow::Node node) { node.getType() instanceof BoolType }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module IdorAccessControlFlow = TaintTracking::Global<IdorAccessControlConfig>;

import IdorAccessControlFlow::PathGraph

from IdorAccessControlFlow::PathNode source, IdorAccessControlFlow::PathNode sink, Callable handler
where
  IdorAccessControlFlow::flowPath(source, sink) and
  handler = source.getNode().getEnclosingCallable() and
  not referencesCurrentUser(handler) and
  not referencesCurrentUser(sink.getNode().getEnclosingCallable()) and
  not isRoleRestricted(handler)
select sink.getNode(), source, sink,
  "This record lookup depends on a $@ without checking that the current user may access the record.",
  source.getNode(), "user-controlled identifier"
