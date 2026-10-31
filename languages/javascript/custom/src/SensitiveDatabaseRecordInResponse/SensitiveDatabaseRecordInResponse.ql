/**
 * @name Database record with sensitive fields sent in an HTTP response
 * @description Sending a whole database record whose model declares a password or
 *              private field in an HTTP response discloses that data to the client.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id js/sensitive-database-record-in-response
 * @tags security
 *       external/cwe/cwe-200
 *       external/cwe/cwe-359
 */

import javascript
import CleartextStorageDatabase.SensitiveDatabaseModels

/**
 * A record whose model declares a password field and does not customize how it is
 * serialized. Private data, such as an address, is often returned to its owner by design,
 * so only password fields are considered.
 */
class SerializedSensitiveRecord extends SensitiveDatabaseRecord {
  SerializedSensitiveRecord() {
    not this.getModelDefinition().hasCustomSerialization() and
    isPasswordFieldName(this.getASensitiveField())
  }

  /** Gets a password field included in this record. */
  string getAPasswordField() { result = this.getASensitiveField() and isPasswordFieldName(result) }
}

/**
 * An object literal that copies a record but overrides a password field, as in
 * `{ ...user.dataValues, password: "********" }`.
 */
class RedactingObjectLiteral extends DataFlow::ObjectLiteralNode {
  RedactingObjectLiteral() {
    exists(ObjectExpr object |
      object = this.asExpr() and
      exists(SpreadProperty spread | spread.getObjectExpr() = object) and
      not exists(SpreadProperty spread, Property password |
        spread.getObjectExpr() = object and
        password.getObjectExpr() = object and
        isPasswordFieldName(password.getName()) and
        spread.getIndex() >= password.getIndex()
      ) and
      not exists(SerializedSensitiveRecord record, string name |
        name = record.getAPasswordField() and
        not exists(Property password |
          password.getObjectExpr() = object and
          password.getName() = name and
          not exists(SpreadProperty spread |
            spread.getObjectExpr() = object and
            spread.getIndex() >= password.getIndex()
          ) and
          not exists(SerializedSensitiveRecord source |
            source.(DataFlow::SourceNode)
              .getAPropertyRead()
              .flowsTo(password.getInit().flow())
          )
        )
      )
    )
  }
}

/** A read of a non-password field, which cannot disclose a password by itself. */
class NonPasswordPropertyRead extends DataFlow::Node instanceof DataFlow::PropRead {
  NonPasswordPropertyRead() {
    exists(string name | name = this.(DataFlow::PropRead).getPropertyName() |
      not name.regexpMatch("[0-9]+") and
      not name = ["dataValues", "_doc", "rows"] and
      not isPasswordFieldName(name)
    )
  }
}

module SensitiveDatabaseRecordInResponseConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof SerializedSensitiveRecord }

  predicate isSink(DataFlow::Node sink) { sink instanceof Http::ResponseSendArgument }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof NonSensitivePropertyRead or
    node instanceof NonPasswordPropertyRead or
    node instanceof HashOrEncryptCall or
    node instanceof RedactingObjectLiteral
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    recordConversionStep(pred, succ)
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet contents) {
    // Assume all properties of a serialized object are themselves sent.
    contents = DataFlow::ContentSet::anyProperty() and
    isSink(node)
  }
}

module SensitiveDatabaseRecordInResponseFlow =
  TaintTracking::Global<SensitiveDatabaseRecordInResponseConfig>;

import SensitiveDatabaseRecordInResponseFlow::PathGraph

from
  SensitiveDatabaseRecordInResponseFlow::PathNode source,
  SensitiveDatabaseRecordInResponseFlow::PathNode sink
where SensitiveDatabaseRecordInResponseFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This HTTP response includes $@, which has the password field " +
    concat(string f |
      f = source.getNode().(SerializedSensitiveRecord).getAPasswordField()
    |
      "'" + f + "'", ", "
    ) + ".", source.getNode(), "a database record"
