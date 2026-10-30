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
import semmle.python.ApiGraphs

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
 * enforces authentication for every route of the app or blueprint), or if an authenticated
 * `before_app_request` hook is registered with the route's app.
 */
predicate isHookAttribute(Attribute hook, string name) {
  hook.getName() = name
}

/** Resolves a request hook to its decorated function or a function passed to the hook. */
predicate resolvesHookToFunction(Attribute hook, Function callback) {
  callback.getADecorator() = hook
  or
  exists(Call c, DataFlow::LocalSourceNode source |
    c.getFunc() = hook and
    source.asExpr() = callback.getDefinition() and
    source.flowsTo(DataFlow::exprNode(c.getArg(0)))
  )
}

/** Unresolved hooks retain the previous exemption to avoid introducing false positives. */
predicate hookAuthenticatesOrIsUnresolved(Attribute hook) {
  not exists(Function callback | resolvesHookToFunction(hook, callback))
  or
  exists(Function callback |
    resolvesHookToFunction(hook, callback) and hasAuthCheckInBody(callback)
  )
}

predicate sameValue(API::Node first, API::Node second) {
  exists(DataFlow::LocalSourceNode source |
    source.flowsTo(first.asSink()) and source.flowsTo(second.asSink())
  )
}

predicate sameValueAsExpression(API::Node value, Expr expression) {
  exists(DataFlow::LocalSourceNode source |
    source.flowsTo(value.asSink()) and source.flowsTo(DataFlow::exprNode(expression))
  )
}

predicate isBlueprintRegistration(API::CallNode call) {
  call = Flask::FlaskApp::instance().getMember("register_blueprint").getACall()
}

predicate routeRunsOnApp(Flask::FlaskRouteSetup route, API::Node app) {
  exists(API::CallNode routeCall |
    routeCall = route and
    (
      routeCall =
        Flask::FlaskApp::instance().getMember("route").getACall() and
      sameValue(routeCall.getSelfParameter(), app)
      or
      exists(API::CallNode registration |
        isBlueprintRegistration(registration) and
        sameValue(routeCall.getSelfParameter(), registration.getParameter(0)) and
        sameValue(registration.getSelfParameter(), app)
      )
    )
  )
}

/** Holds if a resolved app-wide hook protects this route, or its app link is unresolved. */
predicate hasAppWideHook(Function handler, Flask::FlaskRouteSetup route) {
  exists(Attribute hook |
    isHookAttribute(hook, "before_app_request") and
    hookAuthenticatesOrIsUnresolved(hook) and
    (
      not exists(API::CallNode linkedRegistration |
        isBlueprintRegistration(linkedRegistration) and
        sameValueAsExpression(linkedRegistration.getParameter(0), hook.getObject())
      )
      or
      exists(API::Node routeApp, API::CallNode linkedRegistration |
        isBlueprintRegistration(linkedRegistration) and
        sameValueAsExpression(linkedRegistration.getParameter(0), hook.getObject()) and
        routeRunsOnApp(route, routeApp) and
        sameValue(linkedRegistration.getSelfParameter(), routeApp)
      )
      or
      exists(API::CallNode linkedRegistration, API::CallNode routeCall |
        isBlueprintRegistration(linkedRegistration) and
        sameValueAsExpression(linkedRegistration.getParameter(0), hook.getObject()) and
        routeCall = route and
        sameValue(routeCall.getSelfParameter(), linkedRegistration.getParameter(0))
      )
    )
  ) and route.getARequestHandler() = handler
}

predicate hasBeforeRequestHook(Function f) {
  exists(Attribute hook |
    isHookAttribute(hook, "before_request") and
    hook.getEnclosingModule() = f.getEnclosingModule() and
    hookAuthenticatesOrIsUnresolved(hook)
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
  not hasBeforeRequestHook(handler) and
  not hasAppWideHook(handler, route)
select handler, "This route handler $@ but does not perform any authentication check.", op,
  op.getDescription()
