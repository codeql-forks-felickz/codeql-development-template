/**
 * Provides a taint-tracking configuration for static initialization vectors
 * that extends the standard `swift/static-initialization-vector` query with
 * CommonCrypto sinks and with IVs that are stored in global constants or
 * property initializers.
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.security.StaticInitializationVectorQuery
import CredentialAndDataExposure

/** Holds if `source` is a static IV value originating from the literal `origin`. */
predicate isStaticIvSource(DataFlow::Node source, Expr origin) {
  source.asExpr() instanceof StaticInitializationVectorSource and origin = source.asExpr()
  or
  origin = source.(HardcodedNonLocalValue).getOrigin()
}

module ExtendedStaticInitializationVectorConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { isStaticIvSource(node, _) }

  predicate isSink(DataFlow::Node node) { node instanceof StaticInitializationVectorSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof StaticInitializationVectorBarrier }

  predicate isBarrierIn(DataFlow::Node node) {
    // make sources barriers so that we only report the closest instance
    isSource(node)
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    any(StaticInitializationVectorAdditionalFlowStep s).step(nodeFrom, nodeTo)
  }
}

module ExtendedStaticInitializationVectorFlow =
  TaintTracking::Global<ExtendedStaticInitializationVectorConfig>;
