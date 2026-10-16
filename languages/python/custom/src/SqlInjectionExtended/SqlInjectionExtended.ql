/**
 * @name SQL query built from user-controlled sources (extended coverage)
 * @description Building a SQL query from user-controlled sources is vulnerable to insertion of
 *              malicious SQL code by the user. This query only reports SQL queries that are
 *              not already reported by `py/sql-injection`.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id py/sql-injection-extended
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.SqlInjectionCustomizations
import lib.CapturedUnpackingFlow
import lib.DictionaryGetFlow
import lib.DjangoFallbackRouting

/** Same configuration as `py/sql-injection`, without the extensions in this pack. */
module BaselineConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof SqlInjection::Source and
    not source instanceof DjangoFallbackRouting::FallbackViewParameter
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof SqlInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }
}

module BaselineFlow = TaintTracking::Global<BaselineConfig>;

/** `py/sql-injection`, extended with the additional sources and flow steps in this pack. */
module SqlInjectionExtendedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof SqlInjection::Source }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlInjection::Sink and
    not BaselineFlow::flowTo(sink)
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    CapturedUnpackingFlow::step(nodeFrom, nodeTo)
    or
    DictionaryGetFlow::step(nodeFrom, nodeTo)
  }
}

module SqlInjectionExtendedFlow = TaintTracking::Global<SqlInjectionExtendedConfig>;

import SqlInjectionExtendedFlow::PathGraph

from SqlInjectionExtendedFlow::PathNode source, SqlInjectionExtendedFlow::PathNode sink
where SqlInjectionExtendedFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on a $@.", source.getNode(),
  "user-provided value"
