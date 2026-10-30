/**
 * @name Missing authentication for sensitive Flask route
 * @description A Flask route that executes system commands, evaluates code or deserializes
 *              untrusted data without any authentication check can be invoked by anonymous users.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id py/missing-authentication-sensitive-route
 * @tags security
 *       external/cwe/cwe-306
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.Concepts
import semmle.python.frameworks.Flask

/** Holds if `name` looks like it relates to authentication or session state. */
bindingset[name]
predicate isAuthName(string name) {
  name.regexpMatch("(?i).*(auth|login|logged_?in|session|current_?user|permission|privilege|is_?admin|require_?role|jwt|token).*")
}

/** Gets the simple name of decorator expression `e`, e.g. `login_required` for `@flask_login.login_required()`. */
string decoratorName(Expr e) {
  result = e.(Name).getId()
  or
  result = e.(Attribute).getName()
  or
  result = decoratorName(e.(Call).getFunc())
}

/** Holds if `f` is decorated with something that looks like an authentication decorator. */
predicate hasAuthDecorator(Function f) {
  isAuthName(decoratorName(f.getDefinition().(FunctionExpr).getADecorator()))
}

/** Holds if the body of `f` references a name that looks like an authentication or session check. */
predicate hasAuthCheckInBody(Function f) {
  exists(Expr e | e.getScope().getEnclosingScope*() = f |
    isAuthName(e.(Name).getId())
    or
    isAuthName(e.(Attribute).getName())
  )
}

/**
 * Holds if the module containing `f` registers a `before_request` hook (which typically
 * enforces authentication for every route of the app or blueprint), or if an
 * application-wide `before_app_request` hook exists anywhere.
 */
predicate hasBeforeRequestHook(Function f) {
  exists(Attribute a |
    a.getName() = "before_request" and a.getEnclosingModule() = f.getEnclosingModule()
    or
    a.getName() = "before_app_request"
  )
}

/** A dangerous operation that should only be reachable by authenticated users. */
class SensitiveOperation extends DataFlow::Node {
  string description;

  SensitiveOperation() {
    this instanceof SystemCommandExecution and description = "executes a system command"
    or
    this instanceof CodeExecution and description = "executes dynamic code"
    or
    this.(Decoding).mayExecuteInput() and description = "deserializes data unsafely"
  }

  /** Gets a description of this operation. */
  string getDescription() { result = description }
}

from Flask::FlaskRouteSetup route, Function handler, SensitiveOperation op
where
  handler = route.getARequestHandler() and
  op.getScope().getEnclosingScope*() = handler and
  not hasAuthDecorator(handler) and
  not hasAuthCheckInBody(handler) and
  not hasBeforeRequestHook(handler)
select handler, "This route handler $@ but does not perform any authentication check.", op,
  op.getDescription()
