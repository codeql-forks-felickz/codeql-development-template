/**
 * Provides a taint-tracking configuration for finding HTTP requests that carry
 * custom headers (typically an `Authorization` token) and whose URL is
 * controlled by a remote user, for example through a deep link.
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.dataflow.FlowSources
import CredentialAndDataExposure

/** A call to an initializer of `URLRequest` (or its Objective-C counterparts) that takes a URL. */
class UrlRequestInitCall extends CallExpr {
  UrlRequestInitCall() {
    this.getStaticTarget()
        .(Method)
        .hasQualifiedName(["URLRequest", "NSURLRequest", "NSMutableURLRequest"],
          ["init(url:)", "init(url:cachePolicy:timeoutInterval:)"])
  }

  /** Gets the URL argument of this call. */
  Expr getUrlArgument() { result = this.getArgument(0).getExpr() }
}

/** Holds if `e` refers to the local variable `v`, possibly through an `&` (inout) expression. */
private predicate refersToLocal(Expr e, VarDecl v) {
  stripWrappers(e).(DeclRefExpr).getDecl() = v
  or
  stripWrappers(e).(InOutExpr).getSubExpr().(DeclRefExpr).getDecl() = v
}

/**
 * Holds if `header` is a call or assignment that adds an HTTP header to the
 * request created by `init`, for example
 * `request.setValue(token, forHTTPHeaderField: "Authorization")`.
 */
predicate setsHeaderOn(UrlRequestInitCall init, AstNode header) {
  exists(VarDecl request |
    stripWrappers(request.getParentInitializer()) = init and
    (
      exists(CallExpr call |
        call.getStaticTarget()
            .(Method)
            .hasQualifiedName(["URLRequest", "NSMutableURLRequest"],
              ["setValue(_:forHTTPHeaderField:)", "addValue(_:forHTTPHeaderField:)"]) and
        refersToLocal(call.getQualifier(), request) and
        header = call
      )
      or
      exists(AssignExpr assign, MemberRefExpr member |
        member = assign.getDest() and
        member.getMember().(VarDecl).getName() = "allHTTPHeaderFields" and
        refersToLocal(member.getBase(), request) and
        header = assign
      )
    )
  )
}

/** Holds if there is a taint step for parsing URL components from `nodeFrom` to `nodeTo`. */
private predicate urlComponentsStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
  // `URLComponents(url: url, resolvingAgainstBaseURL: _)` and similar
  exists(CallExpr call |
    call.getStaticTarget()
        .(Method)
        .hasQualifiedName(["URLComponents", "NSURLComponents"],
          ["init(url:resolvingAgainstBaseURL:)", "init(string:)"]) and
    nodeFrom.asExpr() = call.getArgument(0).getExpr() and
    nodeTo.asExpr() = call
  )
  or
  // `components.queryItems`, `item.value`, ...
  exists(MemberRefExpr member |
    member.getMember().getEnclosingDecl().asNominalTypeDecl().getName() =
      ["URLComponents", "NSURLComponents", "URLQueryItem", "NSURLQueryItem"] and
    nodeFrom.asExpr() = member.getBase() and
    nodeTo.asExpr() = member
  )
  or
  // `queryItems.first(where: ...)`
  exists(CallExpr call |
    call.getStaticTarget().(Function).getName() = ["first(where:)", "last(where:)"] and
    nodeFrom.asExpr() = call.getQualifier() and
    nodeTo.asExpr() = call
  )
}

module RequestHeadersToUntrustedUrlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node node) {
    exists(UrlRequestInitCall init |
      setsHeaderOn(init, _) and
      node.asExpr() = init.getUrlArgument()
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    storedPropertyJumpStep(nodeFrom, nodeTo) or
    urlComponentsStep(nodeFrom, nodeTo)
  }
}

module RequestHeadersToUntrustedUrlFlow = TaintTracking::Global<RequestHeadersToUntrustedUrlConfig>;
