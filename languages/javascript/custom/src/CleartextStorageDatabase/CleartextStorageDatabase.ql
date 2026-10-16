/**
 * @name Clear text storage of sensitive information in a database
 * @description Persisting passwords or private data to a database without hashing or
 *              encryption exposes it to anyone who can read the database.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id js/clear-text-storage-of-sensitive-data-in-database
 * @tags security
 *       external/cwe/cwe-256
 *       external/cwe/cwe-311
 *       external/cwe/cwe-312
 *       external/cwe/cwe-359
 */

import javascript
import semmle.javascript.security.dataflow.CleartextStorageCustomizations
import SensitiveDatabaseModels

module ClearTextDatabaseStorageConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isSensitiveSource(source, _) or
    source instanceof RemoteFlowSource or
    source instanceof HardcodedSensitiveValue
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof DatabaseStorageSink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof CleartextStorage::Sanitizer or node instanceof HashOrEncryptCall
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Type conversions such as `Number(card.cardNum)` keep the stored value in clear text.
    exists(DataFlow::CallNode call |
      call =
        DataFlow::globalVarRef(["Number", "String", "BigInt", "parseInt", "parseFloat"]).getACall() and
      pred = call.getArgument(0) and
      succ = call
    )
  }
}

module ClearTextDatabaseStorageFlow = TaintTracking::Global<ClearTextDatabaseStorageConfig>;

import ClearTextDatabaseStorageFlow::PathGraph

from
  ClearTextDatabaseStorageFlow::PathNode source, ClearTextDatabaseStorageFlow::PathNode sink,
  string message, string sourceDesc
where
  ClearTextDatabaseStorageFlow::flowPath(source, sink) and
  (
    isSensitiveSource(source.getNode(), sourceDesc) and
    message = "This stores sensitive data returned by $@ in a database as clear text."
    or
    // A remote or hard-coded value is only reported when it is stored in a sensitive
    // field, and only if no sensitive source already explains the same alert.
    (
      sourceDesc = source.getNode().(RemoteFlowSource).getSourceType()
      or
      source.getNode() instanceof HardcodedSensitiveValue and
      sourceDesc = "a hard-coded value"
    ) and
    exists(sink.getNode().(DatabaseStorageSink).getASensitiveField()) and
    message =
      "This stores $@ in the sensitive database field " +
        concat(string f |
          f = sink.getNode().(DatabaseStorageSink).getASensitiveField()
        |
          "'" + f + "'", ", "
        ) + " as clear text." and
    not exists(DataFlow::Node s |
      isSensitiveSource(s, _) and ClearTextDatabaseStorageFlow::flow(s, sink.getNode())
    )
  )
select sink.getNode(), source, sink, message, source.getNode(), sourceDesc
