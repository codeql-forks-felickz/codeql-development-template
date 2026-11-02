/**
 * @name Information exposure through a database error message
 * @description Returning the message of an error raised by a database operation to the
 *              user can reveal connection details, credentials, schema information or
 *              other internals that help an attacker plan further attacks.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.4
 * @precision medium
 * @id go/database-error-exposure
 * @tags security
 *       external/cwe/cwe-209
 *       external/cwe/cwe-497
 */

import go

/** Holds if `pkg` is a package whose errors describe a database or its connection. */
bindingset[pkg]
predicate isDatabasePackage(string pkg) {
  pkg.regexpMatch("database/sql(/driver)?|github\\.com/jmoiron/sqlx|github\\.com/jackc/pgx(/v\\d+)?(/.*)?|github\\.com/lib/pq|github\\.com/go-sql-driver/mysql|github\\.com/mattn/go-sqlite3|go\\.mongodb\\.org/mongo-driver(/v\\d+)?(/.*)?")
}

/** An error returned by a call to a function or method of a database package. */
class DatabaseErrorSource extends DataFlow::Node {
  DatabaseErrorSource() {
    exists(DataFlow::CallNode call |
      isDatabasePackage(call.getTarget().getPackage().getPath()) and
      this = call.getResult(_) and
      this.getType() instanceof ErrorType
    )
  }
}

/**
 * The data argument of a call that executes a `text/template` or
 * `html/template` template, whose output is typically written to an HTTP response.
 */
class TemplateExecutionData extends DataFlow::Node {
  TemplateExecutionData() {
    exists(DataFlow::MethodCallNode call, string pkg, string m |
      call.getTarget().hasQualifiedName(pkg, "Template", m) and
      pkg = ["text/template", "html/template"]
    |
      m = "Execute" and
      exists(Http::ResponseWriter writer | writer.getANode() = call.getArgument(0)) and
      this = call.getArgument(1)
      or
      m = "ExecuteTemplate" and
      exists(Http::ResponseWriter writer | writer.getANode() = call.getArgument(0)) and
      this = call.getArgument(2)
    )
  }
}

module DatabaseErrorExposureConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof DatabaseErrorSource }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof Http::ResponseBody or
    sink instanceof TemplateExecutionData
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // `err.Error()`
    exists(DataFlow::MethodCallNode call |
      call.getTarget().getName() = "Error" and
      call.getNumArgument() = 0 and
      call.getReceiver().getType() instanceof ErrorType and
      pred = call.getReceiver() and
      succ = call.getResult()
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    node.getType() instanceof BoolType or
    node.getType() instanceof NumericType
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    // template data is typically a map or struct holding the error message
    isSink(node) and
    exists(c)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module DatabaseErrorExposureFlow = TaintTracking::Global<DatabaseErrorExposureConfig>;

import DatabaseErrorExposureFlow::PathGraph

from DatabaseErrorExposureFlow::PathNode source, DatabaseErrorExposureFlow::PathNode sink
where DatabaseErrorExposureFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This response exposes the message of $@, which may reveal database internals.", source.getNode(),
  "an error from a database operation"
