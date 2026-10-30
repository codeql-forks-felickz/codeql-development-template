/**
 * @name Missing authorization in state-changing request handler
 * @description A request handler that creates, modifies, or deletes persistent data
 *              without any authentication or authorization check lets any client,
 *              including anonymous users, perform the operation.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id py/missing-authorization-request-handler
 * @tags security
 *       external/cwe/cwe-862
 *       external/cwe/cwe-285
 */

import python
import semmle.python.Concepts
private import semmle.python.dataflow.new.internal.DataFlowDispatch as Dispatch

/**
 * Holds if `name` looks like it refers to an authentication or authorization
 * mechanism, such as `login_required`, `is_authenticated`, `has_perm`,
 * `authorize`, `get_auth_user`, or `LoginRequiredMixin`.
 */
bindingset[name]
predicate isAuthName(string name) {
  name.regexpMatch("(?i).*(authori[sz]|authent|login|logged_?in|perm|user_passes_test|staff|superuser|anonymous|owner|access_?control|is_admin|role_?required).*")
  or
  name.regexpMatch("(?i)(.*_)?auth(_.*)?")
  or
  name.regexpMatch(".*[a-z]Auth([A-Z_].*)?")
}

/** Holds if `e` is a name or attribute that refers to an authentication or authorization mechanism. */
predicate isAuthReference(Expr e) {
  isAuthName(e.(Name).getId()) or
  isAuthName(e.(Attribute).getName())
}

/** Holds if `e`, or one of its sub-expressions, refers to an authentication or authorization mechanism. */
predicate mentionsAuth(Expr e) { isAuthReference(e.getASubExpression*()) }

/** Holds if `c`, or a class it inherits from, is guarded by an authentication or authorization mechanism. */
predicate classMentionsAuth(Class c) {
  exists(Class sc | sc = Dispatch::getADirectSuperclass*(c) |
    mentionsAuth(sc.getADecorator())
    or
    mentionsAuth(sc.getABase())
    or
    exists(Expr e | e.getScope() = sc | isAuthReference(e))
  )
}

/** Holds if `caller` directly calls `callee`. */
predicate calls(Function caller, Function callee) {
  exists(CallNode call |
    Dispatch::resolveCall(call, callee, _) and
    call.getScope() = caller
  )
}

/**
 * Holds if `f` performs, or calls a function that performs, an authentication
 * or authorization check.
 */
predicate checksAuth(Function f) {
  mentionsAuth(f.getADecorator())
  or
  exists(Expr e | e.getScope().getEnclosingScope*() = f | isAuthReference(e))
  or
  classMentionsAuth(f.getScope())
  or
  exists(Function callee | calls(f, callee) and checksAuth(callee))
}

/**
 * Holds if requests are authenticated globally before reaching any request
 * handler, for example by Django's `LoginRequiredMiddleware`, a Flask
 * `before_request` hook, or an aiohttp middleware that checks authentication.
 */
predicate hasGlobalAuthGuard() {
  exists(StringLiteral s | s.getText().regexpMatch("(?i).*login_?required_?middleware.*"))
  or
  exists(Function g |
    checksAuth(g) and
    exists(Expr d | d = g.getADecorator().getASubExpression*() |
      d.(Name).getId() = ["middleware", "before_request", "before_app_request"] or
      d.(Attribute).getName() = ["middleware", "before_request", "before_app_request"]
    )
  )
}

/**
 * Holds if `call` persists a change to application data, such as
 * `obj.save()`, `obj.delete()`, `Model.objects.create(...)`,
 * `Model.create(conn, ...)`, or `queryset.filter(...).update(...)`.
 */
predicate isStateChangingCall(Call call) {
  exists(Attribute func | func = call.getFunc() |
    func.getName() =
      [
        "save", "delete", "create", "bulk_create", "bulk_update", "get_or_create",
        "update_or_create", "set_password"
      ]
    or
    func.getName() = "update" and
    func.getObject().(Call).getFunc().(Attribute).getName() =
      ["filter", "exclude", "all", "select_for_update"]
  )
}

/**
 * Holds if `handler` implements an account flow that is intentionally reachable
 * without authentication, such as login, registration, or password reset.
 */
predicate isPublicAccountFlow(Function handler) {
  handler
      .getName()
      .regexpMatch("(?i).*(login|logout|sign_?in|sign_?up|register|password|reset|activate|verify|confirm).*")
}

from Http::Server::RequestHandler handler, Call write
where
  write =
    min(Call c |
      c.getScope() = handler and isStateChangingCall(c)
    |
      c order by c.getLocation().getStartLine(), c.getLocation().getStartColumn()
    ) and
  not checksAuth(handler) and
  not isPublicAccountFlow(handler) and
  not hasGlobalAuthGuard()
select handler,
  "This request handler performs a state-changing operation ($@) without any authentication or authorization check.",
  write, write.getFunc().(Attribute).getName() + "(...)"
