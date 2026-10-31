/**
 * @name Clear-text logging of sensitive database data
 * @description Logging a whole database record with sensitive fields or a MongoDB
 *              service URL may expose sensitive information.
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

/** A URL for a MongoDB service that may contain database credentials. */
class MongoServiceUrlSource extends DataFlow::Node {
  MongoServiceUrlSource() {
    exists(DataFlow::MethodCallNode call, string serviceName |
      call.getMethodName() = "getServiceURL" and
      serviceName = call.getArgument(0).getStringValue() and
      serviceName.regexpMatch("(?i).*mongo.*") and
      this = call
    )
  }
}

module ClearTextLoggingDatabaseRecordConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
   source instanceof SensitiveDatabaseRecord or
   source instanceof MongoServiceUrlSource
 }

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
  ClearTextLoggingDatabaseRecordFlow::PathNode sink, string message, string sourceDescription
where
  ClearTextLoggingDatabaseRecordFlow::flowPath(source, sink) and
  (
    exists(SensitiveDatabaseRecord record |
      source.getNode() = record and
      message =
        "This logs $@, which includes the sensitive field " +
          concat(string f |
            f = record.getASensitiveField()
          |
            "'" + f + "'", ", "
          ) + ", as clear text." and
      sourceDescription = "a database record"
    )
    or
    source.getNode() instanceof MongoServiceUrlSource and
    message = "This logs $@, which may contain database credentials, as clear text." and
    sourceDescription = "a MongoDB service URL"
  )
select sink.getNode(), source, sink, message, source.getNode(), sourceDescription
