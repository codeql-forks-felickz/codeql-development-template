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
 * Holds if `setting` writes the debug mode of an application identified by `app`.
 */
predicate sameFlaskApplication(DataFlow::Node receiver, DataFlow::Node runReceiver) {
  exists(DataFlow::LocalSourceNode app |
    app.flowsTo(receiver) and
    app.flowsTo(runReceiver)
  )
  or
  exists(DataFlow::ModuleVariableNode app |
    (receiver = app or receiver = app.getARead()) and
    runReceiver = app.getARead()
  )
}

predicate debugModeWriteForApp(ControlFlowNode setting, DataFlow::Node runReceiver) {
  exists(DataFlow::Node value, DataFlow::Node receiver |
    setsDebugMode(setting, value, receiver) and
    sameFlaskApplication(receiver, runReceiver)
  )
}

/**
 * Holds if there is a path from `from` to `to` that does not pass through another
 * write to the debug setting of `app`.
 */
predicate reachesWithoutDebugWrite(
  ControlFlowNode start, ControlFlowNode target, DataFlow::Node runReceiver
) {
  start = target
  or
  exists(ControlFlowNode next |
    start.getASuccessor() = next and
    (next = target or
      not debugModeWriteForApp(next, runReceiver) and
      reachesWithoutDebugWrite(next, target, runReceiver)
    )
  )
}

/**
 * Holds if `setting` sets the debug mode of an application to `value`, through
 * `app.debug = value`, `app.config["DEBUG"] = value` or `app.config.update(DEBUG=value)`.
 */
predicate setsDebugMode(
  ControlFlowNode setting, DataFlow::Node value, DataFlow::Node receiver
) {
  exists(DataFlow::AttrWrite write |
    write.getAttributeName() = "debug" and
    receiver = write.getObject() and
    value = write.getValue() and
    setting = write.asCfgNode()
  )
  or
  exists(SubscriptNode sub, DataFlow::AttrRead config |
    sub.isStore() and
    sub.getIndex().getNode().(StringLiteral).getText() = "DEBUG" and
    config.asCfgNode() = sub.getObject() and
    config.getAttributeName() = "config" and
    receiver = config.getObject() and
    value.asCfgNode() = sub.(DefinitionNode).getValue() and
    setting = sub
  )
  or
  exists(API::CallNode update, DataFlow::AttrRead config |
    update = flaskConfig().getMember("update").getACall() and
    update.(DataFlow::MethodCallNode).getObject() = config and
    config.getAttributeName() = "config" and
    receiver = config.getObject() and
    value = update.getArgByName("DEBUG") and
    setting = update.asCfgNode()
  )
}

from ControlFlowNode setting, DataFlow::Node value, API::CallNode run
where
  isTruthyByDefault(value) and
  runWithoutDebugArgument(run) and
  exists(DataFlow::Node receiver |
    setsDebugMode(setting, value, receiver) and
    sameFlaskApplication(receiver, run.(DataFlow::MethodCallNode).getObject()) and
    reachesWithoutDebugWrite(
      setting, run.asCfgNode(), run.(DataFlow::MethodCallNode).getObject()
    )
  )
select setting,
  "This setting enables Flask debug mode by default before the app is $@. This may allow an attacker to run arbitrary code through the debugger.",
  run, "run"
