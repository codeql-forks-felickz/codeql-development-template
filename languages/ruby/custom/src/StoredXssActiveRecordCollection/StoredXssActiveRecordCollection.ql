/**
 * @name Stored cross-site scripting (including ActiveRecord collections)
 * @description Using uncontrolled stored values in HTML allows for a stored
 *              cross-site scripting vulnerability. This variant of
 *              `rb/stored-xss` additionally treats fields read from records
 *              yielded by iterating an ActiveRecord relation (for example
 *              `Todo.where(...).each { |todo| raw(todo.body) }`) as stored values.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id rb/stored-xss-active-record-collection
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import codeql.ruby.AST
import codeql.ruby.DataFlow
import codeql.ruby.frameworks.ActiveRecord
import codeql.ruby.security.XSS
import codeql.ruby.security.StoredXSSQuery
import StoredXssFlow::PathGraph

/**
 * Gets the name of an `ActiveRecord::Relation` method that returns another
 * relation (or the loaded records) of the same model.
 */
private string relationMethodName() {
  result =
    [
      "all", "where", "rewhere", "not", "or", "and", "merge", "order", "reorder", "reverse_order",
      "in_order_of", "limit", "offset", "joins", "left_joins", "left_outer_joins", "includes",
      "preload", "eager_load", "references", "distinct", "group", "having", "unscoped", "readonly",
      "lock", "strict_loading", "extending", "none", "load", "reload", "records", "to_a", "to_ary"
    ]
}

/**
 * Gets the name of a method that yields each record of a collection as the
 * first parameter of its block.
 */
private string iterationMethodName() {
  result =
    [
      "each", "each_with_index", "each_with_object", "find_each", "map", "collect", "flat_map",
      "collect_concat", "select", "filter", "reject", "filter_map", "sort_by", "group_by",
      "partition", "each_entry"
    ]
}

/**
 * A call that returns an `ActiveRecord::Relation` (or its loaded records) for an
 * `ActiveRecordModelClass`, such as `Todo.where(user_id: id)` or
 * `Todo.all.order(:created_at)`.
 */
private class ActiveRecordRelationCall extends DataFlow::CallNode {
  private ActiveRecordModelClass cls;

  ActiveRecordRelationCall() {
    this.getMethodName() = relationMethodName() and
    (
      this.getReceiver().asExpr().getExpr().(ConstantReadAccess).getAQualifiedName() =
        cls.getAQualifiedName()
      or
      this.getReceiver().getALocalSource().(ActiveRecordRelationCall).getModelClass() = cls
    )
  }

  /** Gets the model class whose records this relation contains. */
  ActiveRecordModelClass getModelClass() { result = cls }
}

/**
 * Tracks ActiveRecord relations to the receiver of a call, including from a
 * controller instance variable into the associated ERB view.
 */
private module RelationTrackingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveRecordRelationCall }

  predicate isSink(DataFlow::Node sink) {
    sink = any(DataFlow::CallNode c | c.getMethodName() = iterationMethodName()).getReceiver()
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    StoredXss::isAdditionalXssTaintStep(node1, node2)
  }
}

private module RelationTracking = DataFlow::Global<RelationTrackingConfig>;

/**
 * A record yielded to the block of an iteration over an ActiveRecord relation,
 * such as `todo` in `Todo.where(...).each { |todo| ... }`.
 */
private class ActiveRecordRelationRecord extends ActiveRecordModelInstantiation,
  DataFlow::ParameterNode
{
  private ActiveRecordRelationCall relation;

  ActiveRecordRelationRecord() {
    exists(DataFlow::CallNode iteration |
      iteration.getMethodName() = iterationMethodName() and
      RelationTracking::flow(relation, iteration.getReceiver()) and
      this = iteration.getBlock().(DataFlow::BlockNode).getParameter(0)
    )
  }

  override ActiveRecordModelClass getClass() { result = relation.getModelClass() }
}

/**
 * A call that reads a database field of a record yielded by iterating an
 * ActiveRecord relation, considered as a source of stored data.
 */
private class ActiveRecordRelationFieldAsSource extends StoredXss::Source instanceof DataFlow::CallNode
{
  ActiveRecordRelationFieldAsSource() {
    exists(ActiveRecordRelationRecord record |
      record.flowsTo(super.getReceiver()) and
      record.methodCallMayAccessField(super.getMethodName()) and
      super.getNumberOfArguments() = 0 and
      not exists(super.getBlock())
    )
  }
}

from StoredXssFlow::PathNode source, StoredXssFlow::PathNode sink
where StoredXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Stored cross-site scripting vulnerability due to $@.",
  source.getNode(), "stored value"
