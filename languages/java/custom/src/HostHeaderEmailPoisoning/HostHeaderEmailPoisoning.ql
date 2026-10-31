/**
 * @name Host header poisoning in reset email content
 * @description An incoming Host header used in an outgoing password reset email can poison the reset link.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision medium
 * @id java/host-header-poisoning
 * @tags security
 *       external/cwe/cwe-640
 */

import java
import semmle.code.java.dataflow.TaintTracking

/** A value read from the incoming HTTP Host header. */
class HostHeaderSource extends DataFlow::Node {
  HostHeaderSource() {
    exists(MethodCall call |
      call.getMethod().hasName("getHeader") and
      call.getMethod()
          .getDeclaringType()
          .hasQualifiedName(["javax.servlet.http", "jakarta.servlet.http"], "HttpServletRequest") and
      call.getArgument(0).(CompileTimeConstantExpr).getStringValue().toLowerCase() = "host" and
      this.asExpr() = call
    )
  }
}

/**
 * Content assigned to an email or mail builder. This includes reset-link
 * messages created through application-specific email DTOs.
 */
class EmailContentSink extends DataFlow::Node {
  EmailContentSink() {
    exists(MethodCall call |
      call.getMethod().hasName(["contents", "setBody", "setText"]) and
      (
        call.getMethod().getDeclaringType().getName().matches("%Email%") or
        call.getMethod().getDeclaringType().getName().matches("%Mail%")
      ) and
      call.getArgument(0) = this.asExpr()
    )
  }
}

/** Taint tracking for Host header values embedded in email content. */
module HostHeaderEmailPoisoningConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof HostHeaderSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof EmailContentSink }
}

module HostHeaderEmailPoisoningFlow = TaintTracking::Global<HostHeaderEmailPoisoningConfig>;

import HostHeaderEmailPoisoningFlow::PathGraph

from HostHeaderEmailPoisoningFlow::PathNode source, HostHeaderEmailPoisoningFlow::PathNode sink
where HostHeaderEmailPoisoningFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This email content depends on the incoming Host header, which may poison a password reset link."
