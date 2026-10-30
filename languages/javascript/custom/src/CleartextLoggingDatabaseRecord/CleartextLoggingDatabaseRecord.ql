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
    recordConversionStep(pred, succ)
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
