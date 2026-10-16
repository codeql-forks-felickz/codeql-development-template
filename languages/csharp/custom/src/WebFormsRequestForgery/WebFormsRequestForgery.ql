/**
 * @name Web Forms state change without CSRF protection
 * @description A Web Forms page that performs a state-changing operation using values read
 *              directly from `Request.Params`, `Request.QueryString` or `Request.Form`, without
 *              anti-forgery validation, can be triggered by a cross-site request (including a
 *              `GET`) from a page controlled by an attacker.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision medium
 * @id cs/web/webforms-request-forgery
 * @tags security
 *       external/cwe/cwe-352
 */

import csharp
import semmle.code.csharp.frameworks.system.Web
import semmle.code.csharp.frameworks.system.web.UI
import semmle.code.csharp.dataflow.TaintTracking

/** Gets a lower-case version of `s`, with camelCase words separated by `_`. */
bindingset[s]
private string splitWords(string s) {
  result = s.regexpReplaceAll("([a-z0-9])([A-Z])", "$1_$2").toLowerCase()
}

/** A Web Forms page class. */
class WebFormsPage extends Class {
  WebFormsPage() { this.getABaseType+() instanceof SystemWebUIPageClass and this.fromSource() }
}

/** An access to `Request.Params`, `Request.QueryString` or `Request.Form`. */
class RawRequestValue extends PropertyAccess {
  RawRequestValue() {
    this.getTarget().getDeclaringType() instanceof SystemWebHttpRequestClass and
    this.getTarget().hasName(["Params", "QueryString", "Form"])
  }
}

/** A call to a source method whose name indicates that it changes state. */
class StateChangingCall extends Call {
  StateChangingCall() {
    this.getTarget().fromSource() and
    splitWords(this.getTarget().getName())
        .regexpMatch("(transfer|withdraw|deposit|pay|purchase|buy|update|delete|remove|insert|create|save|change|edit|modify|approve|cancel|send|submit|reset)(_.*)?")
    or
    this.getTarget().hasName(["ExecuteNonQuery", "ExecuteNonQueryAsync"])
  }
}

/** Holds if `page` calls `System.Web.Helpers.AntiForgery.Validate`. */
predicate validatesAntiForgeryToken(WebFormsPage page) {
  exists(MethodCall mc |
    mc.getTarget().hasFullyQualifiedName("System.Web.Helpers.AntiForgery", "Validate") and
    mc.getEnclosingCallable().getDeclaringType() = page.getABaseType*()
  )
}

/** Holds if `page`, or a base class, binds the view state to the user with `ViewStateUserKey`. */
predicate setsViewStateUserKey(WebFormsPage page) {
  exists(AssignableDefinition def |
    def.getTarget().hasName("ViewStateUserKey") and
    def.getEnclosingCallable().getDeclaringType() = page.getABaseType*()
  )
}

/** Holds if `e` only executes when `IsPostBack` is true. */
predicate isGuardedByPostBack(Expr e) {
  exists(IfStmt ifs |
    ifs.getCondition().(PropertyAccess).getTarget().hasName("IsPostBack") and
    ifs.getThen() = e.getEnclosingStmt().getParent*()
  )
}

module RequestToStateChangeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof RawRequestValue }

  predicate isSink(DataFlow::Node sink) {
    exists(StateChangingCall call | sink.asExpr() = call.getAnArgument())
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    isSink(node) and exists(c)
  }
}

module RequestToStateChange = TaintTracking::Global<RequestToStateChangeConfig>;

/** Holds if the state-changing `call` in `page` uses a value from `source`. */
predicate unprotectedStateChange(WebFormsPage page, StateChangingCall call, DataFlow::Node source) {
  exists(DataFlow::Node sink |
    RequestToStateChange::flow(source, sink) and
    sink.asExpr() = call.getAnArgument() and
    source.asExpr().getEnclosingCallable().getDeclaringType() = page
  ) and
  not validatesAntiForgeryToken(page) and
  not (setsViewStateUserKey(page) and isGuardedByPostBack(call))
}

from StateChangingCall call, DataFlow::Node source
where
  source =
    min(DataFlow::Node s, Location l |
      unprotectedStateChange(_, call, s) and l = s.getLocation()
    |
      s order by l.getStartLine(), l.getStartColumn()
    )
select call,
  "This state-changing call uses a $@ without anti-forgery validation, so it can be triggered by a cross-site request.",
  source, "request parameter"
