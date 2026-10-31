/**
 * @name Email header injection
 * @description User input in an outgoing JavaMail header may allow an attacker to inject additional email headers.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision medium
 * @id java/email-header-injection
 * @tags security
 *       external/cwe/cwe-93
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.ResponseSplittingQuery

/** A value passed to a JavaMail message header setter. */
class JavaMailHeaderSink extends DataFlow::Node {
  JavaMailHeaderSink() {
    exists(MethodCall call, Method method |
      call.getMethod() = method and
      method.getName() = ["setSubject", "setHeader", "addHeader"] and
      method
          .getDeclaringType()
          .getASourceSupertype*()
          .hasQualifiedName(["javax.mail", "jakarta.mail"], "Message") and
      (
        method.hasName("setSubject") and call.getArgument(0) = this.asExpr()
        or
        method.hasName(["setHeader", "addHeader"]) and
        call.getArgument([0, 1]) = this.asExpr()
      )
    )
  }
}

/** Taint tracking for untrusted input flowing to JavaMail message headers. */
module JavaMailHeaderInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { ResponseSplittingConfig::isSource(source) }

  predicate isSink(DataFlow::Node sink) { sink instanceof JavaMailHeaderSink }

  predicate isBarrier(DataFlow::Node node) { ResponseSplittingConfig::isBarrier(node) }
}

module JavaMailHeaderInjectionFlow = TaintTracking::Global<JavaMailHeaderInjectionConfig>;

import JavaMailHeaderInjectionFlow::PathGraph

from JavaMailHeaderInjectionFlow::PathNode source, JavaMailHeaderInjectionFlow::PathNode sink
where JavaMailHeaderInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This email header depends on a $@, which may allow email header injection.", source.getNode(),
  "user-provided value"
