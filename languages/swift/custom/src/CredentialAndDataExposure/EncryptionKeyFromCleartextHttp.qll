/**
 * Provides a taint-tracking configuration for encryption keys that are
 * downloaded over cleartext HTTP and then used for encryption.
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.security.HardcodedEncryptionKeyExtensions
import CredentialAndDataExposure

module EncryptionKeyFromCleartextHttpConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof CleartextHttpResponseData }

  predicate isSink(DataFlow::Node node) { node instanceof HardcodedEncryptionKeySink }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    any(HardcodedEncryptionKeyAdditionalFlowStep s).step(nodeFrom, nodeTo)
  }
}

module EncryptionKeyFromCleartextHttpFlow =
  TaintTracking::Global<EncryptionKeyFromCleartextHttpConfig>;
