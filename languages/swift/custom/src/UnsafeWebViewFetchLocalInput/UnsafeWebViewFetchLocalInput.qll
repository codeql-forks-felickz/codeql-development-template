/**
 * Provides a taint-tracking configuration for reasoning about local user input
 * (for example text typed into a `UITextField`) that is loaded into a WebView.
 *
 * This complements the standard `swift/unsafe-webview-fetch` query, which only
 * considers remote flow sources.
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.dataflow.FlowSources
import codeql.swift.security.UnsafeWebViewFetchExtensions

/**
 * A taint configuration from local user input to WebView fetch sinks (and
 * `baseURL` arguments).
 */
module UnsafeWebViewFetchLocalInputConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node node) {
    exists(UnsafeWebViewFetchSink sink |
      node = sink or
      node.asExpr() = sink.getBaseUrl()
    )
  }

  predicate isBarrier(DataFlow::Node barrier) { barrier instanceof UnsafeWebViewFetchBarrier }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    any(UnsafeWebViewFetchAdditionalFlowStep s).step(nodeFrom, nodeTo)
  }
}

/**
 * Taint flow from local user input to WebView fetch sinks (and `baseURL` arguments).
 */
module UnsafeWebViewFetchLocalInputFlow = TaintTracking::Global<UnsafeWebViewFetchLocalInputConfig>;

/**
 * Holds if `sink` receives local user input and is unsafe because of its
 * `baseURL` argument, as described by `message`.
 */
predicate unsafeWebViewFetchLocalInput(UnsafeWebViewFetchSink sink, string message) {
  UnsafeWebViewFetchLocalInputFlow::flowTo(sink) and
  (
    // no base URL
    not exists(sink.getBaseUrl()) and
    message = "Local user input is used in a WebView fetch."
    or
    // base URL is nil
    sink.getBaseUrl() instanceof NilLiteralExpr and
    message = "Local user input is used in a WebView fetch without restricting the base URL."
    or
    // base URL is also tainted
    UnsafeWebViewFetchLocalInputFlow::flowToExpr(sink.getBaseUrl()) and
    message = "Local user input is used in a WebView fetch with a tainted base URL."
  )
}
