/**
 * @name JDBC connection string injection
 * @description Building a JDBC connection URL from user-provided data allows an attacker
 *              to add delimiters and driver properties that change how the connection
 *              is made, for example selecting another database or enabling dangerous
 *              driver features.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id java/jdbc-connection-string-injection
 * @tags security
 *       external/cwe/cwe-099
 *       external/cwe/cwe-074
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.ExternalFlow
import semmle.code.java.controlflow.Guards
import semmle.code.java.security.Sanitizers
import semmle.code.java.security.RequestForgeryConfig

/**
 * A JDBC connection URL argument, i.e. a `request-forgery` sink of a JDBC driver,
 * data source or connection pool API.
 */
class JdbcUrlSink extends DataFlow::Node {
  JdbcUrlSink() {
    sinkNode(this, "request-forgery") and
    this.getType() instanceof TypeString and
    exists(Call c, RefType t |
      this.asExpr() = c.getAnArgument() and
      t = c.getCallee().getDeclaringType().getSourceDeclaration()
    |
      t.getPackage()
          .hasName([
              "java.sql", "javax.sql", "org.springframework.jdbc.datasource",
              "org.springframework.boot.jdbc", "com.zaxxer.hikari"
            ])
    )
  }
}

/**
 * Holds if `guard` checks `e` against an allowlist (`allowed.contains(e)`) or a
 * constant (`"x".equals(e)`), when evaluating to `branch`.
 */
private predicate allowlistGuard(Guard guard, Expr e, boolean branch) {
  branch = true and
  exists(MethodCall mc | mc = guard |
    mc.getMethod().hasName("contains") and
    mc.getMethod()
        .getDeclaringType()
        .getASourceSupertype*()
        .hasQualifiedName("java.util", "Collection") and
    e = mc.getArgument(0)
    or
    mc.getMethod().getDeclaringType() instanceof TypeString and
    mc.getMethod().hasName(["equals", "equalsIgnoreCase"]) and
    (
      e = mc.getArgument(0) and mc.getQualifier() instanceof CompileTimeConstantExpr
      or
      e = mc.getQualifier() and mc.getArgument(0) instanceof CompileTimeConstantExpr
    )
  )
}

module JdbcConnectionStringInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof JdbcUrlSink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof SimpleTypeSanitizer or
    node instanceof RegexpCheckBarrier or
    node = DataFlow::BarrierGuard<allowlistGuard/3>::getABarrierNode()
  }
}

module JdbcConnectionStringInjectionFlow =
  TaintTracking::Global<JdbcConnectionStringInjectionConfig>;

import JdbcConnectionStringInjectionFlow::PathGraph

from
  JdbcConnectionStringInjectionFlow::PathNode source,
  JdbcConnectionStringInjectionFlow::PathNode sink
where
  JdbcConnectionStringInjectionFlow::flowPath(source, sink) and
  // Flows that control the whole URL (including the host) are already reported by `java/ssrf`.
  not RequestForgeryFlow::flow(source.getNode(), sink.getNode())
select sink.getNode(), source, sink, "This JDBC connection URL depends on a $@.", source.getNode(),
  "user-provided value"
