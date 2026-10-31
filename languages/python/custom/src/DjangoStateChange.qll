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

private predicate isComprehensionScope(Function scope) {
  exists(Comp comprehension | comprehension.getFunction() = scope)
}

private predicate isReferencedNestedScope(Function enclosing, Function nested) {
  exists(FunctionDef definition, Variable variable, Name access |
    definition.getDefinedFunction() = nested and
    definition.defines(variable) and
    access.uses(variable) and
    access.getScope().getEnclosingScope*() = enclosing
  )
  or
  exists(Lambda expression |
    expression.getInnerScope() = nested and
    (
      exists(Call call |
        call.getScope().getEnclosingScope*() = enclosing and
        (
          call.getFunc() = expression
          or
          call.getAnArg() = expression
          or
          call.getAKeyword().getValue() = expression
        )
      )
      or
      exists(Assign assignment, Variable variable, Name access |
        assignment.getValue() = expression and
        assignment.defines(variable) and
        access.uses(variable) and
        access.getScope().getEnclosingScope*() = enclosing
      )
    )
  )
}

/** Holds if `call` is in the view or an invoked/referenced nested scope. */
private predicate isViewExecutionScope(Function f, Scope scope) {
  scope.getEnclosingScope*() = f and
  not exists(Function nested |
    nested = scope.getEnclosingScope*() and
    nested != f and
    not isComprehensionScope(nested) and
    not isReferencedNestedScope(f, nested)
  )
}

predicate performsStateChange(Function f, DjangoStateChangingCall call) {
  isViewExecutionScope(f, call.getScope())
}

/**
 * Holds if `f` reads a credential from a request header, such as an
 * Authorization header or webhook signature.
 */
predicate usesNonCookieAuthentication(Function f) {
  exists(StringLiteral key, Attribute headers |
    headers.getName() in ["headers", "META"] and
    headers.getObject().(Name).getVariable() = f.getArg(0).(Name).getVariable() and
    isViewExecutionScope(f, key.getScope()) and
    key.getText().toLowerCase().regexpMatch(".*(authorization|signature|x-api-key|api_key).*") and
    (
      exists(Subscript subscript |
        subscript.getObject() = headers and subscript.getIndex() = key
      )
      or
      exists(Call lookup, Attribute get |
        get = lookup.getFunc() and
        get.getObject() = headers and
        get.getName() = "get" and
        lookup.getArg(0) = key
      )
    )
  )
}
