/**
 * @name Web view without a navigation policy
 * @description Loading content into a `UIWebView` or `WKWebView` that has no
 *              navigation delegate allows links in the loaded content to
 *              navigate the in-app web view to arbitrary, untrusted sites.
 * @kind problem
 * @problem.severity warning
 * @security-severity 3.5
 * @precision medium
 * @id swift/auth-session-config
 * @tags security
 *       external/cwe/cwe-939
 */

import swift

/**
 * A call that loads a URL request into a `UIWebView` or `WKWebView`.
 */
class WebViewLoadRequestCall extends MethodCallExpr {
  WebViewLoadRequestCall() {
    this.getStaticTarget().(Method).hasQualifiedName("UIWebView", "loadRequest(_:)")
    or
    this.getStaticTarget().(Method).hasQualifiedName("WKWebView", "load(_:)")
  }
}

/**
 * Gets the variable or property that `e` reads, looking through optional
 * unwrapping.
 */
private VarDecl getReferencedVar(Expr e) {
  result = e.(DeclRefExpr).getDecl()
  or
  result = e.(MemberRefExpr).getMember()
  or
  result = getReferencedVar(e.(ForceValueExpr).getSubExpr())
  or
  result = getReferencedVar(e.(BindOptionalExpr).getSubExpr())
}

/**
 * Holds if a (non-`nil`) navigation delegate is assigned to the web view
 * stored in `v`.
 */
private predicate hasNavigationDelegateAssignment(VarDecl v) {
  exists(AssignExpr assign, MemberRefExpr delegate |
    delegate = assign.getDest() and
    (
      delegate.getMember().(FieldDecl).hasQualifiedName("UIWebView", "delegate")
      or
      delegate.getMember().(FieldDecl).hasQualifiedName("WKWebView", "navigationDelegate")
    ) and
    getReferencedVar(delegate.getBase()) = v and
    not assign.getSource() instanceof NilLiteralExpr
  )
}

/**
 * Holds if `t` implements a web view callback that decides whether a
 * navigation is allowed.
 */
private predicate implementsNavigationPolicy(NominalTypeDecl t) {
  exists(Method m |
    m.getEnclosingDecl().asNominalTypeDecl() = t and
    m.getName() =
      [
        "webView(_:shouldStartLoadWith:navigationType:)",
        "webView(_:decidePolicyFor:decisionHandler:)",
        "webView(_:decidePolicyFor:preferences:decisionHandler:)"
      ]
  )
}

from WebViewLoadRequestCall call, VarDecl webView
where
  webView = getReferencedVar(call.getQualifier()) and
  not hasNavigationDelegateAssignment(webView) and
  not implementsNavigationPolicy(call.getEnclosingFunction().getEnclosingDecl().asNominalTypeDecl())
select call,
  "This web view loads content but has no navigation delegate restricting the URLs it may navigate to."
