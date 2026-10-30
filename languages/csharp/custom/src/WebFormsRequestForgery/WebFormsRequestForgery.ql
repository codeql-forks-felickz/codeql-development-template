/**
 * @name Web Forms state change without CSRF protection
 * @description A Web Forms page that performs a state-changing operation using values read
 *              directly from `Request.Params`, `Request.QueryString` or `Request.Form`, or from a
 *              postback event handler, without anti-forgery validation or a user-bound view
 *              state (`ViewStateUserKey`), can be triggered by a cross-site request from a page
 *              controlled by an attacker.
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
        .regexpMatch("(transfer|withdraw|deposit|pay|purchase|buy|charge|place|update|delete|remove|insert|create|save|change|edit|modify|approve|cancel|send|submit|reset)(_.*)?")
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

/**
 * Holds if `page`, a base class, or a master page binds the view state to the user with
 * `ViewStateUserKey`. Master pages are not linked to their content pages in the database, so
 * an assignment in any master page is assumed to apply to all pages.
 */
predicate setsViewStateUserKey(WebFormsPage page) {
  exists(AssignableDefinition def, ValueOrRefType t |
    def.getTarget().hasName("ViewStateUserKey") and
    t = def.getEnclosingCallable().getDeclaringType()
  |
    t = page.getABaseType*()
    or
    t.getABaseType+().hasFullyQualifiedName("System.Web.UI", "MasterPage")
  )
}

/**
 * A postback event handler of a Web Forms page, such as `btnSubmit_Click(object, EventArgs)`.
 * Page lifecycle handlers such as `Page_Load` are excluded.
 */
class PostBackEventHandler extends Method {
  PostBackEventHandler() {
    this.getDeclaringType() instanceof WebFormsPage and
    this.getNumberOfParameters() = 2 and
    this.getParameter(0).getType() instanceof ObjectType and
    this.getParameter(1).getType().getName().matches("%EventArgs") and
    not this.getName().matches("Page\\_%") and
    exists(this.getBody())
  }

  /** Gets a state-changing call performed by this handler, directly or through a method of its page. */
  StateChangingCall getAStateChangingCall() {
    exists(Callable c |
      result.getEnclosingCallable() = c and
      (
        c = this
        or
        this.calls+(c) and
        c.getDeclaringType() = this.getDeclaringType().getABaseType*()
      )
    )
  }
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

from Element alert, string msg, Element related, string relatedLabel
where
  exists(StateChangingCall call |
    alert = call and
    related =
      min(DataFlow::Node s, Location l |
        unprotectedStateChange(_, call, s) and l = s.getLocation()
      |
        s order by l.getStartLine(), l.getStartColumn()
      ).asExpr() and
    msg =
      "This state-changing call uses a $@ without anti-forgery validation, so it can be triggered by a cross-site request." and
    relatedLabel = "request parameter"
  )
  or
  exists(PostBackEventHandler h, WebFormsPage page |
    alert = h and
    page = h.getDeclaringType() and
    not validatesAntiForgeryToken(page) and
    not setsViewStateUserKey(page) and
    related =
      min(StateChangingCall c, Location l |
        c = h.getAStateChangingCall() and l = c.getLocation()
      |
        c order by l.getStartLine(), l.getStartColumn()
      ) and
    msg =
      "This postback event handler performs a $@, but the page does not set ViewStateUserKey or validate an anti-forgery token, so a forged cross-site postback can trigger it." and
    relatedLabel = "state-changing call"
  )
select alert, msg, related, relatedLabel
