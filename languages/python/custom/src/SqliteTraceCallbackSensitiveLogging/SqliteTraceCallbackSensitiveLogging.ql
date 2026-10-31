/**
 * @name Sensitive data logged by SQLite trace callback
 * @description Executing a statement that contains sensitive data on a `sqlite3`
 *              connection with a trace callback enabled writes the (expanded)
 *              statement, including the sensitive data, to the trace output.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.5
 * @precision medium
 * @id py/sqlite-trace-callback-sensitive-logging
 * @tags security
 *       external/cwe/cwe-312
 *       external/cwe/cwe-532
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
import semmle.python.security.dataflow.CleartextLoggingCustomizations

/** Gets a call to `sqlite3.connect`. */
DataFlow::CallCfgNode sqliteConnect() {
  result = API::moduleImport("sqlite3").getMember("connect").getACall()
}

/**
 * Holds if `trace` is a call to `set_trace_callback` on the connection created by `connect`
 * that installs a callback (that is, anything other than `None`).
 */
predicate enablesTracing(DataFlow::CallCfgNode connect, DataFlow::MethodCallNode trace) {
  connect = sqliteConnect() and
  trace = connect.(DataFlow::LocalSourceNode).getAMethodCall("set_trace_callback") and
  not trace.getArg(0).asExpr() instanceof None
}

/**
 * Gets a call executing SQL on the connection created by `connect`, either directly
 * on the connection or on a cursor obtained from it.
 */
DataFlow::MethodCallNode sqlExecution(DataFlow::CallCfgNode connect) {
  connect = sqliteConnect() and
  exists(DataFlow::LocalSourceNode receiver |
    receiver = connect
    or
    receiver = connect.(DataFlow::LocalSourceNode).getAMethodCall("cursor")
  |
    result = receiver.getAMethodCall(["execute", "executemany", "executescript"])
  )
}

/**
 * An argument to a SQL execution call on a `sqlite3` connection that has a trace
 * callback installed before the statement is executed.
 */
class TracedSqlArgument extends DataFlow::Node {
  DataFlow::MethodCallNode trace;

  TracedSqlArgument() {
    exists(DataFlow::CallCfgNode connect, DataFlow::MethodCallNode exec |
      enablesTracing(connect, trace) and
      exec = sqlExecution(connect) and
      trace.asCfgNode().strictlyReaches(exec.asCfgNode()) and
      this in [exec.getArg(_), exec.getArgByName(_)]
    )
  }

  /** Gets the `set_trace_callback` call that enables tracing of this argument. */
  DataFlow::MethodCallNode getTraceCall() { result = trace }
}

private module SqliteTraceLoggingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof CleartextLogging::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof TracedSqlArgument }

  predicate isBarrier(DataFlow::Node node) { node instanceof CleartextLogging::Sanitizer }
}

module SqliteTraceLoggingFlow = TaintTracking::Global<SqliteTraceLoggingConfig>;

import SqliteTraceLoggingFlow::PathGraph

from SqliteTraceLoggingFlow::PathNode source, SqliteTraceLoggingFlow::PathNode sink
where SqliteTraceLoggingFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This SQL statement includes $@ and is written to the output of the $@ enabled on its connection.",
  source.getNode(),
  "sensitive data (" + source.getNode().(CleartextLogging::Source).getClassification() + ")",
  sink.getNode().(TracedSqlArgument).getTraceCall(), "SQLite trace callback"
