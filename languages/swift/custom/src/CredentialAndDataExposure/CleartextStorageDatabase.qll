/**
 * Provides a taint-tracking configuration for cleartext storage of sensitive
 * information in a local database that extends the standard
 * `swift/cleartext-storage-database` query with hard-coded values written to
 * properties with sensitive names (such as `user.password = "secret"`).
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.security.CleartextStorageDatabaseQuery
import CredentialAndDataExposure

module ExtendedCleartextStorageDatabaseConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    CleartextStorageDatabaseConfig::isSource(node) or
    node instanceof HardcodedSensitivePropertyValue
  }

  predicate isSink(DataFlow::Node node) { CleartextStorageDatabaseConfig::isSink(node) }

  predicate isBarrier(DataFlow::Node node) { CleartextStorageDatabaseConfig::isBarrier(node) }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    CleartextStorageDatabaseConfig::isAdditionalFlowStep(nodeFrom, nodeTo)
  }

  predicate isBarrierIn(DataFlow::Node node) {
    // make sources barriers so that we only report the closest instance
    isSource(node)
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    CleartextStorageDatabaseConfig::allowImplicitRead(node, c)
  }
}

module ExtendedCleartextStorageDatabaseFlow =
  TaintTracking::Global<ExtendedCleartextStorageDatabaseConfig>;
