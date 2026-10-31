/**
 * @name Untrusted data in an ODBC connection name
 * @description A command-line value used as an ODBC data source name may alter the connection target.
 * @kind path-problem
 * @precision medium
 * @problem.severity warning
 * @security-severity 5.3
 * @id cpp/odbc-connection-string-injection
 * @tags security
 *       external/cwe/cwe-20
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import OdbcConnectionStringInjection::PathGraph

predicate isCommandLineArgument(DataFlow::Node node) {
 exists(Function main, Parameter argv, ArrayExpr argument |
   main.hasGlobalName(["main", "wmain"]) and
   main.getParameter(1) = argv and
   argument.getArrayBase().getAChild*() = argv.getAnAccess() and
   node.asExpr() = argument
 )
}

module OdbcConnectionStringInjectionConfig implements DataFlow::ConfigSig {
 predicate isSource(DataFlow::Node source) { isCommandLineArgument(source) }

 predicate isSink(DataFlow::Node sink) {
   exists(FunctionCall call |
     call.getTarget().hasGlobalName("SQLConnect") and
     sink.asExpr() = call.getArgument(1)
   )
 }
}

module OdbcConnectionStringInjection =
 TaintTracking::Global<OdbcConnectionStringInjectionConfig>;

from
 OdbcConnectionStringInjection::PathNode source,
 OdbcConnectionStringInjection::PathNode sink
where
 OdbcConnectionStringInjection::flowPath(source, sink) and
select sink.getNode().asExpr(), source, sink,
 "This ODBC data source name comes from $@ and may alter the connection target.",
 source.getNode().asExpr(), "a command-line argument"