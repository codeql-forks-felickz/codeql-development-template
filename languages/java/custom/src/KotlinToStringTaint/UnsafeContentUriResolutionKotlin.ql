/**
 * @name Uncontrolled data used in content resolution (Kotlin `toString`)
 * @description Resolving externally-provided content URIs without validation can allow
 *              an attacker to access unexpected resources. This variant of
 *              `java/android/unsafe-content-uri-resolution` additionally tracks taint
 *              through Kotlin `toString()` calls on `Uri` and `CharSequence` receivers,
 *              for example `Uri.fromFile(File(uri.toString()))`.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id java/android/unsafe-content-uri-resolution-kotlin
 * @tags security
 *       external/cwe/cwe-441
 *       external/cwe/cwe-610
 */

import java
import semmle.code.java.security.UnsafeContentUriResolutionQuery
import KotlinToStringTaint

module KotlinUnsafeContentResolutionConfig implements DataFlow::ConfigSig {
  predicate isSource = UnsafeContentResolutionConfig::isSource/1;

  predicate isSink = UnsafeContentResolutionConfig::isSink/1;

  predicate isBarrier = UnsafeContentResolutionConfig::isBarrier/1;

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    UnsafeContentResolutionConfig::isAdditionalFlowStep(node1, node2)
    or
    kotlinToStringTaintStep(node1, node2)
  }
}

module KotlinUnsafeContentResolutionFlow =
  TaintTracking::Global<KotlinUnsafeContentResolutionConfig>;

import KotlinUnsafeContentResolutionFlow::PathGraph

from
  KotlinUnsafeContentResolutionFlow::PathNode src, KotlinUnsafeContentResolutionFlow::PathNode sink
where
  KotlinUnsafeContentResolutionFlow::flowPath(src, sink) and
  // Only report results that the standard query does not already report.
  not UnsafeContentResolutionFlow::flow(src.getNode(), sink.getNode())
select sink.getNode(), src, sink,
  "This ContentResolver method that resolves a URI depends on a $@.", src.getNode(),
  "user-provided value"
