/**
 * @name URL redirection from remote source in http4k
 * @description URL redirection based on unvalidated user-input
 *              may cause redirection to malicious web sites.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id java/unvalidated-url-redirection
 * @tags security
 *       external/cwe/cwe-601
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.UrlRedirect

private class Http4kResponseLocationSink extends UrlRedirectSink {
  Http4kResponseLocationSink() {
    exists(MethodCall call |
      call.getMethod().getDeclaringType().hasQualifiedName("org.http4k.core", "Response") and
      call.getMethod().hasName(["header", "replaceHeader"]) and
      call.getArgument(0).(CompileTimeConstantExpr).getStringValue().toLowerCase() = "location" and
      this.asExpr() = call.getArgument(1)
    )
  }
}

module Http4kUrlRedirectConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof UrlRedirectSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof UrlRedirectSanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module Http4kUrlRedirectFlow = TaintTracking::Global<Http4kUrlRedirectConfig>;

import Http4kUrlRedirectFlow::PathGraph

from Http4kUrlRedirectFlow::PathNode source, Http4kUrlRedirectFlow::PathNode sink
where Http4kUrlRedirectFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Untrusted URL redirection depends on a $@.", source.getNode(),
  "user-provided value"
