/**
 * @name Mass assignment of user-controlled ownership or privilege field
 * @description Permitting ownership or privilege attributes (such as `creator_id` or `admin`)
 *              from request parameters and mass-assigning them to a record lets a user
 *              act on behalf of, or with the privileges of, another user.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id rb/insecure-mass-assignment-sensitive-field
 * @tags security
 *       external/cwe/cwe-639
 *       external/cwe/cwe-915
 */

import codeql.ruby.AST
import codeql.ruby.controlflow.CfgNodes
import codeql.ruby.DataFlow
import codeql.ruby.TaintTracking
import codeql.ruby.dataflow.RemoteFlowSources
import codeql.ruby.security.MassAssignmentCustomizations

/**
 * Holds if `name` is the name of an attribute that identifies the owner of a record
 * or grants privileges, and so should never be taken from the client.
 */
bindingset[name]
predicate isSensitiveFieldName(string name) {
  name.regexpMatch("(?i)(creator|owner|user|author|sender|account|created_by|updated_by)_id|(is_)?admin|roles?")
}

/** Gets the name of a sensitive field that is permitted by the `permit` call `permit`. */
string getAPermittedSensitiveField(DataFlow::CallNode permit) {
  permit.getMethodName() = "permit" and
  permit.getArgument(_).getConstantValue().isStringlikeValue(result) and
  isSensitiveFieldName(result)
}

/**
 * A call to `permit` on request parameters whose allowlist contains an ownership or
 * privilege field.
 */
class SensitivePermitCall extends DataFlow::CallNode {
  SensitivePermitCall() {
    exists(getAPermittedSensitiveField(this)) and
    exists(RemoteFlowSource source | TaintTracking::localTaint(source, this.getReceiver()))
  }
}

/** Holds if `call` sets the field `name` via a keyword argument or a hash literal argument. */
predicate setsField(DataFlow::CallNode call, string name) {
  exists(call.getKeywordArgument(name))
  or
  call.getArgument(_)
      .asExpr()
      .(ExprNodes::HashLiteralCfgNode)
      .getAKeyValuePair()
      .getKey()
      .getConstantValue()
      .isStringlikeValue(name)
}

module SensitiveFieldMassAssignmentConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof SensitivePermitCall }

  predicate isSink(DataFlow::Node node) { node instanceof MassAssignment::Sink }

  predicate isBarrier(DataFlow::Node node) {
    // The sensitive field is overridden server-side, e.g. `params.merge(creator_id: current_user.id)`.
    exists(DataFlow::CallNode merge, string name |
      merge.getMethodName() = ["merge", "merge!"] and
      setsField(merge, name) and
      isSensitiveFieldName(name) and
      node = merge
    )
    or
    // The sensitive field is removed, e.g. `params.except(:creator_id)`.
    exists(DataFlow::CallNode except, string name |
      except.getMethodName() = ["except", "without"] and
      except.getArgument(_).getConstantValue().isStringlikeValue(name) and
      isSensitiveFieldName(name) and
      node = except
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module SensitiveFieldMassAssignmentFlow = TaintTracking::Global<SensitiveFieldMassAssignmentConfig>;

import SensitiveFieldMassAssignmentFlow::PathGraph

/**
 * Holds if the sensitive field `name` is explicitly assigned to the mass-assigned record
 * in the same method as `sink`, e.g. `record.creator_id = current_user.id`.
 */
predicate overriddenInSameMethod(DataFlow::Node sink, string name) {
  exists(DataFlow::CallNode set, DataFlow::CallNode massAssignment |
    set.asExpr().getExpr().(SetterMethodCall).getMethodName() = name + "=" and
    set.asExpr().getExpr().getEnclosingCallable() = sink.asExpr().getExpr().getEnclosingCallable() and
    massAssignment.getArgument(_) = sink and
    (
      massAssignment.getMethodName() = ["update", "update!"] and
      DataFlow::localFlow(massAssignment.getReceiver(), set.getReceiver())
      or
      not massAssignment.getMethodName() = ["update", "update!"] and
      DataFlow::localFlow(massAssignment, set.getReceiver())
    )
  )
}

from
  SensitiveFieldMassAssignmentFlow::PathNode source,
  SensitiveFieldMassAssignmentFlow::PathNode sink, string fields
where
  SensitiveFieldMassAssignmentFlow::flowPath(source, sink) and
  fields =
    strictconcat(string name |
      name = getAPermittedSensitiveField(source.getNode()) and
      not overriddenInSameMethod(sink.getNode(), name)
    |
      "'" + name + "'", ", "
    )
select sink.getNode(), source, sink,
  "This mass assignment can set the ownership or privilege attribute(s) " + fields +
    " from $@, allowing a user to act as another user or escalate privileges.", source.getNode(),
  "a user-controlled parameter allowlist"
