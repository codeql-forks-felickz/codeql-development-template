/**
 * Provides predicates for finding Django views that perform server-side state
 * changes, used by the custom CSRF queries in this pack.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs
import semmle.python.frameworks.Django

private module Models = PrivateDjango::DjangoImpl::DB::Models;

/**
 * A call that persists a state change through the Django ORM or the
 * authentication framework, such as `obj.save()`, `obj.delete()`,
 * `Model.objects.filter(...).update(...)` or `user.set_password(...)`.
 */
class DjangoStateChangingCall extends DataFlow::CallCfgNode {
  string operation;

  DjangoStateChangingCall() {
    exists(DataFlow::MethodCallNode call | call = this |
      // Model instance methods.
      call.calls(Models::Model::instance(_), operation) and
      operation in ["save", "delete"]
      or
      // Changing a user's password (the user object usually comes from
      // `request.user`, which is not modeled as a model instance).
      call.getMethodName() = operation and
      operation = "set_password"
    )
    or
    // Manager and query-set methods that write to the database.
    operation in [
        "create", "update", "delete", "bulk_create", "bulk_update", "get_or_create",
        "update_or_create"
      ] and
    this = [Models::manager(_), Models::querySet(_)].getMember(operation).getACall()
  }

  /** Gets the name of the state-changing operation, for example `save`. */
  string getOperation() { result = operation }
}

/** Holds if `call` is a state-changing call inside `f` (including nested scopes). */
predicate performsStateChange(Function f, DjangoStateChangingCall call) {
  call.getScope().getEnclosingScope*() = f
}

/**
 * Holds if `f` appears to authenticate requests with something other than
 * cookies, for example an `Authorization` header or a webhook signature,
 * so that a cross-site request cannot carry the credentials.
 */
predicate usesNonCookieAuthentication(Function f) {
  exists(StringLiteral s | s.getScope().getEnclosingScope*() = f |
    s.getText().toLowerCase().regexpMatch(".*(authorization|signature|x-api-key|api_key).*")
  )
}
