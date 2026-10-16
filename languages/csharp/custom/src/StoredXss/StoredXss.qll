/**
 * Provides a taint-tracking configuration for reasoning about stored cross-site
 * scripting (XSS) vulnerabilities, where data read back from a database is
 * written to HTML or JavaScript.
 */

import csharp
private import semmle.code.csharp.security.dataflow.XSSQuery as Xss
private import semmle.code.csharp.security.dataflow.XSSSinks as XssSinks
private import semmle.code.csharp.security.dataflow.flowsources.Stored

/**
 * A taint-tracking configuration for stored XSS.
 *
 * Sources are database reads (Entity Framework mapped properties, data readers,
 * raw SQL queries and `database` source models), independently of the threat
 * models enabled for the analysis. Sinks and sanitizers are shared with the
 * standard `cs/web/xss` query.
 */
module StoredXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof DatabaseInputSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof XssSinks::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Xss::Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Taint tracking for stored XSS vulnerabilities. */
module StoredXssFlow = TaintTracking::Global<StoredXssConfig>;
