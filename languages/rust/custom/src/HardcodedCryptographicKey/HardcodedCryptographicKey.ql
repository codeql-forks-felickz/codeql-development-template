/**
 * @name Hard-coded cryptographic key or passphrase
 * @description Using a hard-coded key or passphrase with a cryptographic API
 *              lets anyone with access to the source code or binary decrypt
 *              or forge protected data.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id rust/hardcoded-cryptographic-key
 * @tags security
 *       external/cwe/cwe-321
 *       external/cwe/cwe-798
 */

import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking
import codeql.rust.security.HardcodedCryptographicValueExtensions
import common.CryptoKeyMaterial

/**
 * A taint-tracking configuration for hard-coded keys and passphrases flowing to
 * cryptographic APIs, including APIs and conversions that are not modeled by
 * `codeql/rust-all`.
 */
module HardcodedCryptographicKeyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof HardcodedCryptographicValue::Source
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof CryptographicKeySink }

  predicate isBarrier(DataFlow::Node barrier) {
    barrier instanceof HardcodedCryptographicValue::Barrier
    or
    // the buffer is overwritten with random bytes
    isRandomlyFilledBuffer(barrier.asExpr())
  }

  predicate isBarrierIn(DataFlow::Node node) {
    // make sources barriers so that we only report the closest instance
    isSource(node)
  }

  predicate isBarrierOut(DataFlow::Node node) {
    // make sinks barriers so that we only report the closest instance
    isSink(node)
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    keyMaterialConversionStep(node1, node2)
  }
}

module HardcodedCryptographicKeyFlow = TaintTracking::Global<HardcodedCryptographicKeyConfig>;

/**
 * The configuration used by the standard `rust/hard-coded-cryptographic-value`
 * query, used to avoid reporting results that query already reports.
 */
module StandardHardcodedCryptographicValueConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof HardcodedCryptographicValue::Source
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof HardcodedCryptographicValue::Sink }

  predicate isBarrier(DataFlow::Node barrier) {
    barrier instanceof HardcodedCryptographicValue::Barrier
  }

  predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

  predicate isBarrierOut(DataFlow::Node node) { isSink(node) }
}

module StandardHardcodedCryptographicValueFlow =
  TaintTracking::Global<StandardHardcodedCryptographicValueConfig>;

import HardcodedCryptographicKeyFlow::PathGraph

from HardcodedCryptographicKeyFlow::PathNode source, HardcodedCryptographicKeyFlow::PathNode sink
where
  HardcodedCryptographicKeyFlow::flowPath(source, sink) and
  not StandardHardcodedCryptographicValueFlow::flow(source.getNode(), sink.getNode())
select source.getNode(), source, sink, "This hard-coded value is used as $@.", sink,
  sink.getNode().(CryptographicKeySink).getKind().getDescription()
