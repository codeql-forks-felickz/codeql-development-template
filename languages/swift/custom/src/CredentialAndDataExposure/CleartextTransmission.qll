/**
 * Provides a taint-tracking configuration for cleartext transmission of
 * sensitive information that extends the standard `swift/cleartext-transmission`
 * query with sensitive user interface inputs (such as `ssnField`) as sources.
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.security.CleartextTransmissionQuery
import CredentialAndDataExposure

module ExtendedCleartextTransmissionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    CleartextTransmissionConfig::isSource(node) or
    node.asExpr() instanceof SensitiveUiInputExpr
  }

  predicate isSink(DataFlow::Node node) { CleartextTransmissionConfig::isSink(node) }

  predicate isBarrier(DataFlow::Node node) { CleartextTransmissionConfig::isBarrier(node) }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    CleartextTransmissionConfig::isAdditionalFlowStep(nodeFrom, nodeTo)
  }

  predicate isBarrierIn(DataFlow::Node node) {
    // make sources barriers so that we only report the closest instance
    isSource(node)
  }
}

module ExtendedCleartextTransmissionFlow =
  TaintTracking::Global<ExtendedCleartextTransmissionConfig>;
