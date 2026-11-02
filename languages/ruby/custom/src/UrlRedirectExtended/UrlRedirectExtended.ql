/**
 * @name URL redirection from remote source (extended coverage)
 * @description URL redirection based on unvalidated user input
 *              may cause redirection to malicious web sites. This query
 *              extends `rb/url-redirection` to post-login style redirects
 *              in non-GET Rails actions, `Hash#update`-style parameter
 *              merges and standalone controller-action snippets.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @sub-severity low
 * @id rb/url-redirection-extended
 * @tags security
 *       external/cwe/cwe-601
 * @precision high
 */

import codeql.ruby.AST
import codeql.ruby.Concepts
import codeql.ruby.DataFlow
import codeql.ruby.TaintTracking
import codeql.ruby.frameworks.ActionController
import codeql.ruby.frameworks.Rails
import codeql.ruby.security.UrlRedirectQuery as Stock

/**
 * Holds if `name` is a conventional name for a request parameter that holds
 * the target of a redirect (for example the `url` or `return_to` value that a
 * login page carries from its query string into the login form).
 */
bindingset[name]
predicate isRedirectTargetParamName(string name) {
  name.regexpMatch("(?i)([a-z0-9]+_)*(url|uri|redirect(_?to|_?url|_?uri)?|return(_?to|_?url|_?uri)?|next|continue|goto|dest(ination)?|came_?from)")
}

/**
 * A method defined at the top level of a file, outside of any class or
 * module, as found in standalone controller-action snippets.
 */
class TopLevelMethod extends Method {
  TopLevelMethod() { this.getEnclosingModule() instanceof Toplevel }
}

/**
 * A call on `self` (usually receiver-less) inside a `TopLevelMethod` that does not resolve to any
 * method defined in the database, so it is assumed to be the Rails controller
 * API of the same name.
 */
class UnresolvedSnippetCall extends MethodCall {
  UnresolvedSnippetCall() {
    this.getReceiver() instanceof SelfVariableAccess and
    this.getEnclosingMethod() instanceof TopLevelMethod and
    not exists(this.getATarget())
  }
}

/** A Rails `params` call in a standalone controller-action snippet. */
class SnippetParamsSource extends DataFlow::Node {
  SnippetParamsSource() {
    exists(UnresolvedSnippetCall c | c = this.asExpr().getExpr() |
      c.getMethodName() = "params" and
      c.getNumberOfArguments() = 0 and
      not exists(c.getBlock())
    )
  }
}

/**
 * The URL argument of a Rails `redirect_to` call in a standalone
 * controller-action snippet.
 */
class SnippetRedirectSink extends DataFlow::Node {
  SnippetRedirectSink() {
    exists(UnresolvedSnippetCall c |
      (
        c.getMethodName() = ["redirect_to", "redirect_back_or_to"] and
        this.asExpr().getExpr() = c.getArgument(0)
        or
        c.getMethodName() = "redirect_back" and
        this.asExpr().getExpr() = c.getKeywordArgument("fallback_location")
      ) and
      (
        c.getMethodName() != "redirect_to" or
        not c.getKeywordArgument("allow_other_host").getConstantValue().isBoolean(false)
      )
    )
  }
}

/** Holds if `n` is a Rails `params` call, either in a controller or in a snippet. */
predicate isParamsCall(DataFlow::Node n) {
  n.asExpr().getExpr() instanceof Rails::ParamsCall or n instanceof SnippetParamsSource
}

/**
 * A read of a redirect-target parameter, such as `params[:url]` or
 * `params.fetch(:return_to)`.
 */
class RedirectTargetParamRead extends DataFlow::CallNode {
  RedirectTargetParamRead() {
    (
      isParamsCall(this.getReceiver()) or
      exists(DataFlow::LocalSourceNode src |
        src.flowsTo(this.getReceiver()) and
        isParamsCall(src)
      )
    ) and
    this.getMethodName() = ["[]", "fetch", "dig"] and
    exists(string name |
      this.getArgument(0).getConstantValue().isStringlikeValue(name) and
      isRedirectTargetParamName(name)
    )
  }
}

/**
 * The location of a redirect in a Rails action that is not a stock
 * `rb/url-redirection` sink because the action is not expected to handle GET
 * requests (for example a login `create` action).
 */
class NonGetActionRedirectSink extends DataFlow::Node {
  NonGetActionRedirectSink() {
    exists(Http::Server::HttpRedirectResponse e |
      this = e.getRedirectLocation() and
      this.asExpr().getExpr().getEnclosingMethod() instanceof ActionControllerActionMethod and
      forall(RedirectToCall c | c = e.asExpr().getExpr() | c.allowsExternalRedirect())
    ) and
    not this instanceof Stock::Sink
  }
}

/** Flow states distinguishing redirect-target parameters from other input. */
newtype TRedirectFlowState =
  /** Any remote user input. */
  TAnyInput() or
  /** A request parameter conventionally used as a redirect target. */
  TRedirectTargetParam()

module UrlRedirectExtendedConfig implements DataFlow::StateConfigSig {
  class FlowState = TRedirectFlowState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    (source instanceof Stock::Source or source instanceof SnippetParamsSource) and
    state = TAnyInput()
    or
    source instanceof RedirectTargetParamRead and state = TRedirectTargetParam()
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    (sink instanceof Stock::Sink or sink instanceof SnippetRedirectSink) and
    state = TAnyInput()
    or
    sink instanceof NonGetActionRedirectSink and state = TRedirectTargetParam()
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof Stock::Sanitizer }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    Stock::UrlRedirect::isAdditionalTaintStep(node1, node2)
    or
    // `Hash#update` and `Hash#merge!` return the (possibly tainted) receiver.
    exists(DataFlow::CallNode c |
      c.getMethodName() = ["update", "merge!"] and
      node1 = c.getReceiver() and
      node2 = c
    )
  }
}

module UrlRedirectExtendedFlow = TaintTracking::GlobalWithState<UrlRedirectExtendedConfig>;

import UrlRedirectExtendedFlow::PathGraph

from UrlRedirectExtendedFlow::PathNode source, UrlRedirectExtendedFlow::PathNode sink
where
  UrlRedirectExtendedFlow::flowPath(source, sink) and
  // Only report redirects that the stock `rb/url-redirection` query misses.
  not Stock::UrlRedirectFlow::flowTo(sink.getNode())
select sink.getNode(), source, sink, "Untrusted URL redirection depends on a $@.", source.getNode(),
  "user-provided value"
