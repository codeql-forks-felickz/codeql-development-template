/**
 * @name LDAP query built from user-controlled sources
 * @description Building an LDAP query (search filter or distinguished name) from
 *              user-controlled data without escaping LDAP special characters can
 *              allow a malicious user to alter the meaning of the query.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id cpp/ldap-injection
 * @tags security
 *       external/cwe/cwe-090
 */

import cpp
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.ir.dataflow.TaintTracking
import LdapInjectionFlow::PathGraph

module LdapInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof FlowSource }

  // sinks and barriers defined using models-as-data (see `models/cwe-90.model.yml`)
  predicate isSink(DataFlow::Node node) { sinkNode(node, "ldap-injection") }

  predicate isBarrier(DataFlow::Node node) {
    node.asExpr().getUnspecifiedType() instanceof IntegralType
    or
    barrierNode(node, "ldap-injection")
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module LdapInjectionFlow = TaintTracking::Global<LdapInjectionConfig>;

from
  FlowSource taintSource, LdapInjectionFlow::PathNode sourceNode,
  LdapInjectionFlow::PathNode sinkNode
where
  LdapInjectionFlow::flowPath(sourceNode, sinkNode) and
  taintSource = sourceNode.getNode()
select sinkNode.getNode(), sourceNode, sinkNode, "This LDAP query depends on $@.", taintSource,
  "user input (" + taintSource.getSourceType() + ")"
