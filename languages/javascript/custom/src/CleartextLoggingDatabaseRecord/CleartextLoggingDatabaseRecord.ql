/**
 * @name Clear-text logging of a database record with sensitive fields
 * @description Logging a whole database record whose model declares a password or
 *              private field writes that data to the application logs.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id js/clear-text-logging-of-sensitive-database-record
 * @tags security
 *       external/cwe/cwe-312
 *       external/cwe/cwe-359
 *       external/cwe/cwe-532
 */

import javascript
import semmle.javascript.security.dataflow.CleartextLoggingCustomizations
import CleartextStorageDatabase.SensitiveDatabaseModels

/** A record read through a model that exposes a password or private field. */
class SensitiveDatabaseRecord extends DataFlow::Node {
  OrmModelDefinition def;

  SensitiveDatabaseRecord() {
    this = def.getARecord() and
    def.hasExposedSensitivePath(_)
  }

  /** Gets a sensitive field included in this record. */
  string getASensitiveField() { def.hasExposedSensitivePath(result) }
}

/**
 * A read of a named property that is neither sensitive nor a way to reach the record
 * contents, such as `user.username` or `users.length`.
 */
class NonSensitivePropertyRead extends DataFlow::Node instanceof DataFlow::PropRead {
  NonSensitivePropertyRead() {
    exists(string name | name = super.getPropertyName() |
      not name.regexpMatch("[0-9]+") and
      not name = ["dataValues", "_doc", "rows"] and
      not isSensitiveFieldName(name)
    )
  }
}

module ClearTextLoggingDatabaseRecordConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof SensitiveDatabaseRecord }

  predicate isSink(DataFlow::Node sink) { sink instanceof CleartextLogging::Sink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof CleartextLogging::Barrier or
    node instanceof NonSensitivePropertyRead or
    node instanceof HashOrEncryptCall
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    CleartextLogging::isAdditionalTaintStep(pred, succ)
    or
    // Converting a record to a plain object keeps its fields.
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = ["toJSON", "toObject", "get"] and
      pred = call.getReceiver() and
      succ = call
    )
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet contents) {
    // Assume all properties of a logged object are themselves logged.
    contents = DataFlow::ContentSet::anyProperty() and
    isSink(node)
  }
}

module ClearTextLoggingDatabaseRecordFlow =
  TaintTracking::Global<ClearTextLoggingDatabaseRecordConfig>;

import ClearTextLoggingDatabaseRecordFlow::PathGraph

from
  ClearTextLoggingDatabaseRecordFlow::PathNode source,
  ClearTextLoggingDatabaseRecordFlow::PathNode sink
where ClearTextLoggingDatabaseRecordFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This logs $@, which includes the sensitive field " +
    concat(string f |
      f = source.getNode().(SensitiveDatabaseRecord).getASensitiveField()
    |
      "'" + f + "'", ", "
    ) + ", as clear text.", source.getNode(), "a database record"
