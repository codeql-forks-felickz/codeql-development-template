/**
 * @name Flask app run in debug mode via the `debug` attribute or `DEBUG` config
 * @description Enabling debug mode through `app.debug` or `app.config["DEBUG"]` (for example,
 *              from an environment variable lookup with a truthy default) before running the
 *              Flask development server may allow an attacker to run arbitrary code through
 *              the debugger.
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

/** Gets a reference to the `config` mapping of a Flask application. */
API::Node flaskConfig() { result = Flask::FlaskApp::instance().getMember("config") }

/**
 * Holds if `setting` sets the debug mode of a Flask application to `value`, through
 * `app.debug = value`, `app.config["DEBUG"] = value` or `app.config.update(DEBUG=value)`.
 */
predicate setsDebugMode(ControlFlowNode setting, DataFlow::Node value) {
  exists(DataFlow::AttrWrite write |
    write.getAttributeName() = "debug" and
    write.getObject() = Flask::FlaskApp::instance().getAValueReachableFromSource() and
    value = write.getValue() and
    setting = write.asCfgNode()
  )
  or
  exists(SubscriptNode sub |
    sub.isStore() and
    sub.getIndex().getNode().(StringLiteral).getText() = "DEBUG" and
    sub.getObject() = flaskConfig().getAValueReachableFromSource().asCfgNode() and
    value.asCfgNode() = sub.(DefinitionNode).getValue() and
    setting = sub
  )
  or
  exists(API::CallNode update |
    update = flaskConfig().getMember("update").getACall() and
    value = update.getArgByName("DEBUG") and
    setting = update.asCfgNode()
  )
}

from ControlFlowNode setting, DataFlow::Node value, API::CallNode run
where
  setsDebugMode(setting, value) and
  isTruthyByDefault(value) and
  runWithoutDebugArgument(run) and
  setting.strictlyReaches(run.asCfgNode())
select setting,
  "This setting enables Flask debug mode by default before the app is $@. This may allow an attacker to run arbitrary code through the debugger.",
  run, "run"
