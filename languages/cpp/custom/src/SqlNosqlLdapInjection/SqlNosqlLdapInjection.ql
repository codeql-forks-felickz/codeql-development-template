/**
 * @name LDAP query built from user-controlled sources
 * @description Building an LDAP search filter from user-controlled data without
 *              escaping LDAP metacharacters allows a malicious user to change
 *              the meaning of the query (LDAP injection).
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
import semmle.code.cpp.dataflow.ExternalFlow
import LdapInjection::PathGraph

/**
 * An LDAP search function from the WinLDAP (`Wldap32`) or OpenLDAP APIs, such as
 * `ldap_search_ext_sA`, `ldap_search_sW` or `ldap_search_ext_s`. In all of these
 * functions the search filter is the fourth argument.
 */
class LdapSearchFunction extends Function {
  LdapSearchFunction() {
    exists(string name |
      name =
        [
          "ldap_search", "ldap_search_s", "ldap_search_st", "ldap_search_ext", "ldap_search_ext_s",
          "ldap_search_init_page"
        ]
    |
      this.hasGlobalName([name, name + "A", name + "W"])
    )
  }

  /** Gets the index of the search filter parameter. */
  int getFilterParameterIndex() { result = 3 }
}

/**
 * A function that escapes LDAP filter metacharacters, such as OpenLDAP's
 * `ldap_bv2escaped_filter_value` or a user-defined `escape_ldap_filter`.
 */
class LdapEscapeFunction extends Function {
  LdapEscapeFunction() {
    this.getName().regexpMatch("(?i).*filter.*(escape|sanitize|encode).*") or
    this.getName().regexpMatch("(?i).*(escape|sanitize|encode).*filter.*")
  }
}

/** Gets the expression of a filter argument passed to an LDAP search function call. */
Expr getAnLdapFilterArgument() {
  exists(FunctionCall call, LdapSearchFunction f |
    call.getTarget() = f and
    result = call.getArgument(f.getFilterParameterIndex())
  )
}

module LdapInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof FlowSource }

  predicate isSink(DataFlow::Node node) {
    node.asIndirectArgument() = getAnLdapFilterArgument()
    or
    node.asExpr() = getAnLdapFilterArgument()
    or
    // sink defined using models-as-data
    sinkNode(node, "ldap-injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    node.asExpr().getUnspecifiedType() instanceof IntegralType
    or
    exists(FunctionCall call | call.getTarget() instanceof LdapEscapeFunction |
      node.asExpr() = call or
      node.asIndirectExpr() = call or
      node.asDefiningArgument() = call.getAnArgument()
    )
    or
    // barrier defined using models-as-data
    barrierNode(node, "ldap-injection")
  }

  predicate isBarrierOut(DataFlow::Node node) {
    // Only block taint at sanitized values that leave an escaping function.
    node.getEnclosingCallable().getUnderlyingCallable() instanceof LdapEscapeFunction and
    (
      node.asExpr().getParent() instanceof ReturnStmt
      or
      exists(Expr arg | node.asDefiningArgument() = arg)
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module LdapInjection = TaintTracking::Global<LdapInjectionConfig>;

from LdapInjection::PathNode source, LdapInjection::PathNode sink, FlowSource taintSource
where
  LdapInjection::flowPath(source, sink) and
  taintSource = source.getNode()
select sink.getNode(), source, sink,
  "This LDAP search filter depends on a $@ and is not escaped, which may allow LDAP injection.",
  taintSource, "user-provided value (" + taintSource.getSourceType() + ")"
