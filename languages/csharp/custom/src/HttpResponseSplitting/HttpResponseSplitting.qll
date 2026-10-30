/**
 * Provides a taint-tracking configuration for reasoning about HTTP response
 * splitting (CWE-113) vulnerabilities in ASP.NET (`System.Web`) applications.
 */

import csharp
private import semmle.code.csharp.security.Sanitizers
private import semmle.code.csharp.security.dataflow.flowsources.FlowSources
private import semmle.code.asp.WebConfig

/**
 * A `System.Web` HTTP response type, `HttpResponse` or `HttpResponseBase`, or a subtype.
 *
 * Other HTTP stacks (`System.Net.HttpListenerResponse`, ASP.NET Core) reject CR/LF
 * characters in header values, so they are not considered here.
 */
class SystemWebResponseType extends RefType {
  SystemWebResponseType() {
    this.getABaseType*().hasFullyQualifiedName("System.Web", ["HttpResponse", "HttpResponseBase"])
  }
}

/** A data flow sink for HTTP response splitting vulnerabilities. */
abstract class HttpResponseSplittingSink extends DataFlow::ExprNode { }

/** The value argument of `AddHeader` or `AppendHeader` on a `System.Web` response. */
private class AddHeaderSink extends HttpResponseSplittingSink {
  AddHeaderSink() {
    exists(MethodCall mc |
      mc.getTarget().hasName(["AddHeader", "AppendHeader"]) and
      mc.getTarget().getDeclaringType() instanceof SystemWebResponseType and
      this.getExpr() = mc.getArgument(1)
    )
  }
}

/** An access to the `Headers` collection of a `System.Web` response. */
private class ResponseHeadersAccess extends PropertyAccess {
  ResponseHeadersAccess() {
    this.getTarget().hasName("Headers") and
    this.getTarget().getDeclaringType() instanceof SystemWebResponseType
  }
}

/**
 * The value written to a `System.Web` response `Headers` collection, through
 * `Headers.Add(name, value)`, `Headers.Set(name, value)` or `Headers[name] = value`.
 */
private class ResponseHeadersWriteSink extends HttpResponseSplittingSink {
  ResponseHeadersWriteSink() {
    exists(MethodCall mc |
      exists(ResponseHeadersAccess headers |
        DataFlow::localExprFlow(headers, mc.getQualifier())
      ) and
      mc.getTarget().hasName(["Add", "Set"]) and
      this.getExpr() = mc.getArgument(1)
    )
    or
    exists(AssignExpr ae, IndexerAccess ia |
      ia = ae.getLValue() and
      exists(ResponseHeadersAccess headers |
        DataFlow::localExprFlow(headers, ia.getQualifier())
      ) and
      this.getExpr() = ae.getRValue()
    )
  }
}

/** The value assigned to `RedirectLocation` (the `Location` header) of a `System.Web` response. */
private class RedirectLocationSink extends HttpResponseSplittingSink {
  RedirectLocationSink() {
    exists(AssignExpr ae, PropertyAccess pa |
      pa = ae.getLValue() and
      pa.getTarget().hasName("RedirectLocation") and
      pa.getTarget().getDeclaringType() instanceof SystemWebResponseType and
      this.getExpr() = ae.getRValue()
    )
  }
}

/** A sanitizer for HTTP response splitting vulnerabilities. */
abstract class HttpResponseSplittingSanitizer extends DataFlow::ExprNode { }

private class SimpleTypeSanitizer extends HttpResponseSplittingSanitizer, SimpleTypeSanitizedExpr {
}

private class GuidSanitizer extends HttpResponseSplittingSanitizer, GuidSanitizedExpr { }

/** URL encoding percent-encodes carriage return and line feed characters. */
private class UrlEncodeSanitizer extends HttpResponseSplittingSanitizer {
  UrlEncodeSanitizer() { this.getExpr() instanceof UrlSanitizedExpr }
}

/**
 * A call to `string.Replace` that replaces a carriage return or line feed character,
 * for example `s.Replace("\n", "")`.
 */
private class NewLineReplaceSanitizer extends HttpResponseSplittingSanitizer {
  NewLineReplaceSanitizer() {
    exists(MethodCall mc, MethodCall previous, string old, string previousOld |
      mc = this.getExpr() and
      mc.getTarget().hasFullyQualifiedName("System", "String", "Replace") and
      (
        old = mc.getArgument(0).(StringLiteral).getValue() or
        old = mc.getArgument(0).(CharLiteral).getValue()
      ) and
      (old = "\r" or old = "\n") and
      isNewlineFreeReplacement(mc.getArgument(1)) and
      previous = mc.getQualifier() and
      previous.getTarget().hasFullyQualifiedName("System", "String", "Replace") and
      (
        previousOld = previous.getArgument(0).(StringLiteral).getValue() or
        previousOld = previous.getArgument(0).(CharLiteral).getValue()
      ) and
      (previousOld = "\r" or previousOld = "\n") and
      old != previousOld and
      isNewlineFreeReplacement(previous.getArgument(1))
    )
  }
}

private predicate isNewlineFreeReplacement(Expr replacement) {
  exists(string value |
    (
      value = replacement.(StringLiteral).getValue() or
      value = replacement.(CharLiteral).getValue()
    ) and
    not value.regexpMatch("(?s).*[\\r\\n].*")
  )
  or replacement.getValue() = ""
  or
  exists(FieldAccess fa |
    fa = replacement and
    fa.getTarget().hasName("Empty") and
    fa.getTarget().getDeclaringType().hasFullyQualifiedName("System", "String")
  )
}

/**
 * Holds if ASP.NET header checking (which encodes CR/LF characters in header values)
 * is disabled, either in a configuration file (`<httpRuntime enableHeaderChecking="false" />`)
 * or programmatically through `HttpRuntimeSection.EnableHeaderChecking`. This mirrors the
 * logic of `cs/web/disabled-header-checking`.
 */
predicate headerCheckingDisabled() {
  exists(HttpRuntimeXmlElement e |
    e.getAttribute("enableHeaderChecking").getValue().toLowerCase() = "false"
  )
  or
  exists(Assignment a, PropertyAccess pa |
    a.getLeftOperand() = pa and
    pa.getTarget().hasName("EnableHeaderChecking") and
    pa.getTarget()
        .getDeclaringType()
        .hasFullyQualifiedName("System.Web.Configuration", "HttpRuntimeSection") and
    a.getRightOperand().getValue() = "false"
  )
}

/**
 * Gets a note to append to alert messages describing whether ASP.NET header
 * checking is known to be disabled.
 */
string headerCheckingNote() {
  if headerCheckingDisabled()
  then
    result =
      " ASP.NET header checking is disabled for this application, so CR/LF characters are not encoded."
  else result = ""
}

/** A taint-tracking configuration for HTTP response splitting vulnerabilities. */
module HttpResponseSplittingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof HttpResponseSplittingSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof HttpResponseSplittingSanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Taint tracking for HTTP response splitting vulnerabilities. */
module HttpResponseSplittingFlow = TaintTracking::Global<HttpResponseSplittingConfig>;
