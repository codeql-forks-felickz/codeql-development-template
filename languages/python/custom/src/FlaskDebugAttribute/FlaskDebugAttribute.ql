/**
 * @name Flask app run in debug mode via the `debug` attribute
 * @description Enabling debug mode through `app.debug` (for example, from an environment
 *              variable lookup with a truthy default) before running the Flask development
 *              server may allow an attacker to run arbitrary code through the debugger.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id py/custom/flask-debug-attribute
 * @tags security
 *       external/cwe/cwe-215
 *       external/cwe/cwe-489
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs
import semmle.python.frameworks.Flask

/**
 * Gets a call that reads an environment variable with an explicit default value,
 * such as `os.environ.get(name, default)` or `os.getenv(name, default)`.
 */
API::CallNode envLookupWithDefault() {
  result = API::moduleImport("os").getMember("environ").getMember("get").getACall()
  or
  result = API::moduleImport("os").getMember("getenv").getACall()
}

/**
 * Holds if `value` is truthy by default: either a truthy literal (such as `True`, `1`
 * or any non-empty string like `"False"`), or an environment variable lookup whose
 * default is a truthy literal.
 */
predicate isTruthyByDefault(DataFlow::Node value) {
  exists(DataFlow::LocalSourceNode src | src.flowsTo(value) |
    src.asExpr().(ImmutableLiteral).booleanValue() = true
    or
    exists(API::CallNode env | env = envLookupWithDefault() and src = env |
      env.getParameter(1, "default")
          .getAValueReachingSink()
          .asExpr()
          .(ImmutableLiteral)
          .booleanValue() = true
    )
  )
}

/**
 * Holds if `run` is a call to `run` on a Flask application that does not pass a
 * `debug` argument, so the value of `app.debug` is used.
 */
predicate runWithoutDebugArgument(API::CallNode run) {
  run = Flask::FlaskApp::instance().getMember("run").getACall() and
  not exists(run.getArg(2)) and
  not exists(run.getArgByName("debug"))
}

from DataFlow::AttrWrite write, API::CallNode run
where
  write.getAttributeName() = "debug" and
  write.getObject() = Flask::FlaskApp::instance().getAValueReachableFromSource() and
  isTruthyByDefault(write.getValue()) and
  runWithoutDebugArgument(run) and
  write.asCfgNode().strictlyReaches(run.asCfgNode())
select write,
  "This assignment enables Flask debug mode by default before the app is $@. This may allow an attacker to run arbitrary code through the debugger.",
  run, "run"
