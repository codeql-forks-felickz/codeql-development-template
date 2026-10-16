/**
 * @name Server-side request forgery (extended)
 * @description Making a network request to a URL that is controlled by a remote user allows
 *              the user to reach internal services or cloud metadata endpoints through the server.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id cs/request-forgery-extended
 * @tags security
 *       external/cwe/cwe-918
 */

import csharp
import semmle.code.csharp.controlflow.Guards
import semmle.code.csharp.frameworks.Format
import semmle.code.csharp.security.Sanitizers
import semmle.code.csharp.security.dataflow.flowsources.FlowSources

/** A sink for server-side request forgery: the destination of an outgoing request. */
abstract class RequestForgerySink extends DataFlow::ExprNode { }

/** A barrier for server-side request forgery. */
abstract class RequestForgeryBarrier extends DataFlow::Node { }

/** Holds if `t` is `System.String` or `System.Uri`. */
private predicate isUrlType(Type t) {
  t instanceof StringType or
  t.(Class).hasFullyQualifiedName("System", "Uri")
}

/** The URL argument to a `HttpClient` request method, for example `GetAsync(url)`. */
private class HttpClientRequestSink extends RequestForgerySink {
  HttpClientRequestSink() {
    exists(MethodCall mc, Method m |
      m = mc.getTarget() and
      m.getDeclaringType().getABaseType*().hasFullyQualifiedName("System.Net.Http", "HttpClient") and
      m.hasName([
          "DeleteAsync", "GetAsync", "GetByteArrayAsync", "GetStreamAsync", "GetStringAsync",
          "PatchAsync", "PostAsync", "PutAsync"
        ]) and
      isUrlType(m.getParameter(0).getType()) and
      this.getExpr() = mc.getArgument(0)
    )
  }
}

/** The URL argument to a `new HttpRequestMessage(method, url)` constructor call. */
private class HttpRequestMessageSink extends RequestForgerySink {
  HttpRequestMessageSink() {
    exists(ObjectCreation oc, Constructor c |
      c = oc.getTarget() and
      c.getDeclaringType().hasFullyQualifiedName("System.Net.Http", "HttpRequestMessage") and
      isUrlType(c.getParameter(1).getType()) and
      this.getExpr() = oc.getArgument(1)
    )
  }
}

/** The URL argument to `WebRequest.Create`, `WebRequest.CreateHttp` or `WebRequest.CreateDefault`. */
private class WebRequestCreateSink extends RequestForgerySink {
  WebRequestCreateSink() {
    exists(MethodCall mc, Method m |
      m = mc.getTarget() and
      m.getDeclaringType().hasFullyQualifiedName("System.Net", "WebRequest") and
      m.hasName(["Create", "CreateHttp", "CreateDefault"]) and
      this.getExpr() = mc.getArgument(0)
    )
  }
}

/**
 * The address argument to a `WebClient` request method, for example `DownloadString(url)`,
 * `UploadString(url, data)` or `OpenRead(url)`.
 */
private class WebClientRequestSink extends RequestForgerySink {
  WebClientRequestSink() {
    exists(MethodCall mc, Method m |
      m = mc.getTarget() and
      m.getDeclaringType().getABaseType*().hasFullyQualifiedName("System.Net", "WebClient") and
      m.getName()
          .regexpMatch("(Download(Data|File|String)|Upload(Data|File|String|Values)|Open(Read|Write))(Async|TaskAsync)?") and
      m.getParameter(0).hasName(["address", "uri"]) and
      isUrlType(m.getParameter(0).getType()) and
      this.getExpr() = mc.getArgument(0)
    )
  }
}

/** A value assigned to `HttpClient.BaseAddress`, `WebClient.BaseAddress` or `HttpRequestMessage.RequestUri`. */
private class RequestAddressPropertySink extends RequestForgerySink {
  RequestAddressPropertySink() {
    exists(Property p |
      p.hasFullyQualifiedName("System.Net.Http", "HttpClient", "BaseAddress") or
      p.hasFullyQualifiedName("System.Net", "WebClient", "BaseAddress") or
      p.hasFullyQualifiedName("System.Net.Http", "HttpRequestMessage", "RequestUri")
    |
      this.getExpr() = p.getAnAssignedValue()
    )
  }
}

/**
 * Holds if `s` is a constant URL prefix that fixes the scheme and host of the request,
 * for example `"https://api.example.com/"` or `"https://api.example.com?q="`.
 */
bindingset[s]
private predicate isHostFixingPrefix(string s) {
  s.regexpMatch("(?is)[a-z][a-z0-9+.-]*://[^/?#@\\\\]+[/?#].*")
}

/**
 * A string built from a constant prefix that fixes the host, so user input can only
 * influence the path or query of the request.
 */
private class HostFixingConcatenationBarrier extends RequestForgeryBarrier {
  HostFixingConcatenationBarrier() {
    isHostFixingPrefix(this.asExpr().(AddExpr).getLeftOperand().getValue())
    or
    isHostFixingPrefix(this.asExpr().(InterpolatedStringExpr).getText(0).getValue())
    or
    exists(FormatCall fc |
      this.asExpr() = fc and
      isHostFixingPrefix(fc.getFormatExpr().getValue())
    )
  }
}

/** Holds if `g` checks `e` against a trusted base with `Uri.IsBaseOf`. */
private predicate isBaseOfGuard(Guard g, Expr e, GuardValue v) {
  exists(MethodCall mc | mc = g |
    mc.getTarget().hasFullyQualifiedName("System", "Uri", "IsBaseOf") and
    e = [mc.getArgument(0), mc.getQualifier()] and
    v.asBooleanValue() = true
  )
}

/** Holds if `g` checks that `e` starts with a constant prefix that fixes the host. */
private predicate hostPrefixGuard(Guard g, Expr e, GuardValue v) {
  exists(MethodCall mc | mc = g |
    mc.getTarget().hasFullyQualifiedName("System", "String", "StartsWith") and
    isHostFixingPrefix(mc.getArgument(0).getValue()) and
    e = mc.getQualifier() and
    v.asBooleanValue() = true
  )
}

/** Holds if `g` checks that `e` is contained in an allowlist, for example `allowed.Contains(e)`. */
private predicate allowListGuard(Guard g, Expr e, GuardValue v) {
  exists(MethodCall mc | mc = g |
    mc.getTarget().hasName("Contains") and
    not mc.getQualifier().getType() instanceof StringType and
    e = mc.getArgument(0) and
    v.asBooleanValue() = true
  )
}

/** Holds if `g` compares the `Host` of URI `e` for equality, for example `uri.Host == "example.com"`. */
private predicate hostComparisonGuard(Guard g, Expr e, GuardValue v) {
  exists(EqualityOperation cmp, PropertyAccess pa | cmp = g |
    pa = cmp.getAnOperand() and
    pa.getProperty().hasFullyQualifiedName("System", "Uri", ["Host", "Authority"]) and
    e = pa.getQualifier() and
    if cmp instanceof EQExpr then v.asBooleanValue() = true else v.asBooleanValue() = false
  )
}

private class GuardBarrier extends RequestForgeryBarrier {
  GuardBarrier() {
    this = DataFlow::BarrierGuard<isBaseOfGuard/3>::getABarrierNode() or
    this = DataFlow::BarrierGuard<hostPrefixGuard/3>::getABarrierNode() or
    this = DataFlow::BarrierGuard<allowListGuard/3>::getABarrierNode() or
    this = DataFlow::BarrierGuard<hostComparisonGuard/3>::getABarrierNode()
  }
}

private class SimpleTypeBarrier extends RequestForgeryBarrier {
  SimpleTypeBarrier() {
    this instanceof SimpleTypeSanitizedExpr or
    this instanceof GuidSanitizedExpr
  }
}

module RequestForgeryConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof RequestForgerySink }

  predicate isBarrier(DataFlow::Node node) { node instanceof RequestForgeryBarrier }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module RequestForgeryFlow = TaintTracking::Global<RequestForgeryConfig>;

import RequestForgeryFlow::PathGraph

from RequestForgeryFlow::PathNode source, RequestForgeryFlow::PathNode sink
where RequestForgeryFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "The URL of this request depends on a $@.", source.getNode(),
  "user-provided value"
