/**
 * @name Database query built from user-controlled sources in a NoSQL logical operator
 * @description Using user-controlled values as sub-documents of a NoSQL `$and`, `$or` or
 *              `$nor` operator lets a malicious user inject query operators such as `$ne`.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id js/nosql-injection-logical-operator
 * @tags security
 *       external/cwe/cwe-943
 */

import javascript
import semmle.javascript.security.dataflow.NosqlInjectionQuery as Nosql

/**
 * Gets a source node for a query document that is interpreted by a NoSQL query that `root`
 * flows to, either `root` itself or a sub-document of a `$and`, `$or` or `$nor` operator
 * nested (transitively) within `root`.
 */
private DataFlow::SourceNode queryDocument(DataFlow::SourceNode root) {
  exists(NoSql::Query query | root.flowsTo(query)) and
  result = root
  or
  exists(DataFlow::SourceNode parent, DataFlow::SourceNode clauses |
    parent = queryDocument(root) and
    clauses.flowsTo(parent.getAPropertyWrite(["$and", "$or", "$nor"]).getRhs())
  |
    result.flowsTo(clauses.getAPropertyWrite().getRhs())
    or
    result.flowsTo(clauses.getAMethodCall("push").getAnArgument())
  )
}

module NosqlInjectionLogicalOperatorConfig implements DataFlow::StateConfigSig {
  import semmle.javascript.security.CommonFlowState

  predicate isSource(DataFlow::Node source, FlowState state) {
    Nosql::NosqlInjectionConfig::isSource(source, state)
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    Nosql::NosqlInjectionConfig::isSink(sink, state)
  }

  predicate isBarrier(DataFlow::Node node, FlowState state) {
    Nosql::NosqlInjectionConfig::isBarrier(node, state)
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    Nosql::NosqlInjectionConfig::isAdditionalFlowStep(node1, state1, node2, state2)
    or
    // a tainted object stored in a nested logical-operator sub-document taints the root query
    state1.isTaintedObject() and
    state2.isTaintedObject() and
    exists(DataFlow::SourceNode root, DataFlow::SourceNode subDocument |
      subDocument = queryDocument(root) and
      subDocument != root and
      node1 = subDocument.getAPropertyWrite().getRhs() and
      root.flowsTo(node2)
    )
  }
}

module NosqlInjectionLogicalOperatorFlow =
  DataFlow::GlobalWithState<NosqlInjectionLogicalOperatorConfig>;

import NosqlInjectionLogicalOperatorFlow::PathGraph

from
  NosqlInjectionLogicalOperatorFlow::PathNode source,
  NosqlInjectionLogicalOperatorFlow::PathNode sink
where
  NosqlInjectionLogicalOperatorFlow::flowPath(source, sink) and
  // only report flows that are not already reported by `js/sql-injection`
  not Nosql::NosqlInjectionFlow::flow(source.getNode(), sink.getNode())
select sink.getNode(), source, sink, "This query object depends on a $@.", source.getNode(),
  "user-provided value"
