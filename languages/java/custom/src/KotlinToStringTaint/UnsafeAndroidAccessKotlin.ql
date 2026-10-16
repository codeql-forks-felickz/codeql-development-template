/**
 * @name Unsafe resource fetching in Android WebView (Kotlin `toString`)
 * @description JavaScript rendered inside WebViews can access protected resources
 *              whose locations are controlled by untrusted user input. This variant
 *              of `java/android/unsafe-android-webview-fetch` additionally tracks taint
 *              through Kotlin `toString()` calls on `CharSequence` (for example
 *              `EditText.text.toString()`) and `Uri` receivers.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision medium
 * @id java/android/unsafe-android-webview-fetch-kotlin
 * @tags security
 *       external/cwe/cwe-749
 *       external/cwe/cwe-079
 */

import java
import semmle.code.java.security.UnsafeAndroidAccessQuery
import KotlinToStringTaint

module KotlinFetchUntrustedResourceConfig implements DataFlow::ConfigSig {
  predicate isSource = FetchUntrustedResourceConfig::isSource/1;

  predicate isSink = FetchUntrustedResourceConfig::isSink/1;

  predicate isBarrier = FetchUntrustedResourceConfig::isBarrier/1;

  predicate isAdditionalFlowStep = kotlinToStringTaintStep/2;
}

module KotlinFetchUntrustedResourceFlow = TaintTracking::Global<KotlinFetchUntrustedResourceConfig>;

import KotlinFetchUntrustedResourceFlow::PathGraph

from
  KotlinFetchUntrustedResourceFlow::PathNode source,
  KotlinFetchUntrustedResourceFlow::PathNode sink
where
  KotlinFetchUntrustedResourceFlow::flowPath(source, sink) and
  // Only report results that the standard query does not already report.
  not FetchUntrustedResourceFlow::flow(source.getNode(), sink.getNode())
select sink.getNode(), source, sink, "Unsafe resource fetching in Android WebView due to $@.",
  source.getNode(), sink.getNode().(UrlResourceSink).getSinkType()
