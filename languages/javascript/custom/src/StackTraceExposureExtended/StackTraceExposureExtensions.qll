/**
 * Provides a taint-tracking configuration for reasoning about exposure of error
 * messages and stack traces, extending the sources, sinks and barriers of the
 * standard `js/stack-trace-exposure` query.
 */

import javascript
import semmle.javascript.security.dataflow.StackTraceExposureCustomizations

/** Holds if `cond` checks that the application runs in the `development` environment. */
private predicate isDevelopmentCheck(Expr cond) {
  exists(EqualityTest eq |
    eq = cond.getUnderlyingValue() and
    eq.getPolarity() = true and
    eq.getAnOperand().getStringValue() = "development" and
    isApplicationEnvironmentValue(eq.getAnOperand())
  )
}

/** Holds if `value` reads an application environment value. */
private predicate isApplicationEnvironmentValue(Expr value) {
  value.flow().getALocalSource() =
    DataFlow::globalVarRef("process").getAPropertyRead("env").getAPropertyRead("NODE_ENV")
  or
  exists(DataFlow::MethodCallNode get |
    get = value.flow().getALocalSource() and
    get.getMethodName() = "get" and
    get.getArgument(0).getStringValue() = "env" and
    isExpressApplicationReference(get.getReceiver())
  )
}

/** Holds if `receiver` refers to an Express application. */
private predicate isExpressApplicationReference(DataFlow::Node receiver) {
  receiver.getALocalSource() = Express::appCreation()
  or
  exists(PropAccess app |
    app = receiver.asExpr() and
    app.getPropertyName() = "app" and
    Express::isRequest(DataFlow::valueNode(app.getBase()))
  )
}

/**
 * Holds if `nd` is only evaluated when the application runs in the `development`
 * environment, for example `env === 'development' ? err : {}`.
 */
private predicate isDevelopmentOnly(DataFlow::Node nd) {
  exists(ConditionalExpr c |
    isDevelopmentCheck(c.getCondition()) and
    c.getConsequent() = nd.asExpr().getParent*()
  )
  or
  exists(IfStmt i |
    isDevelopmentCheck(i.getCondition()) and
    i.getThen() = nd.asExpr().getParent+()
  )
}

/**
 * The error parameter of an Express error-handling middleware, for example `err`
 * in `app.use((err, req, res, next) => { ... })`.
 */
class ExpressErrorParameter extends StackTraceExposure::Source {
  ExpressErrorParameter() { this = any(Express::RouteHandler rh).getRouteHandlerParameter("error") }
}

/**
 * The error parameter of a Node.js-style callback, for example `err` in
 * `db.all(sql, function (err, rows) { ... })`.
 */
class CallbackErrorParameter extends StackTraceExposure::Source, DataFlow::ParameterNode {
  CallbackErrorParameter() {
    exists(DataFlow::InvokeNode call, DataFlow::FunctionNode cb |
      cb = call.getLastArgument().getALocalSource() and
      this = cb.getParameter(0) and
      this.getName().regexpMatch("(?i)(e|err|error)")
    )
  }
}

/**
 * The parameter of a promise rejection handler, for example `err` in
 * `p.catch(err => ...)` or `reason` in `p.then(onFulfilled, reason => ...)`.
 */
class PromiseRejectionParameter extends StackTraceExposure::Source {
  PromiseRejectionParameter() {
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "catch" and
      this = call.getCallback(0).getParameter(0)
      or
      call.getMethodName() = "then" and
      this = call.getCallback(1).getParameter(0)
    )
  }
}

/**
 * An instance of the `errorhandler` middleware installed with `use(...)`. The
 * middleware sends the message and stack trace of every unhandled error to the
 * client, so it is both a source and a sink.
 */
class ErrorHandlerMiddleware extends StackTraceExposure::Source, StackTraceExposure::Sink,
  DataFlow::CallNode
{
  ErrorHandlerMiddleware() {
    this = DataFlow::moduleImport("errorhandler").getACall() and
    exists(DataFlow::MethodCallNode use |
      use.getMethodName() = "use" and
      this.flowsTo(use.getAnArgument()) and
      not isDevelopmentOnly(use)
    )
  }
}

/** Holds if `nd` reads a property of an error that holds its message or stack trace. */
private predicate isErrorDetailRead(DataFlow::Node nd) {
  nd.(DataFlow::PropRead).getPropertyName() = ["stack", "message"]
}

/**
 * A taint-tracking configuration for reasoning about exposure of error messages
 * and stack traces.
 */
module StackTraceExposureExtendedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof StackTraceExposure::Source }

  predicate isBarrier(DataFlow::Node nd) {
    // read of a property other than `stack` or `message`
    exists(nd.(DataFlow::PropRead).getPropertyName()) and
    not isErrorDetailRead(nd)
    or
    // `toString` does not include the stack trace
    nd.(DataFlow::MethodCallNode).getMethodName() = "toString"
    or
    // converting the error itself to a string does not include the stack trace,
    // but concatenating its message or stack trace does
    nd = StringConcatenation::getAnOperand(_) and
    not isErrorDetailRead(nd) and
    not exists(StringConcatenation::getAnOperand(nd))
    or
    isDevelopmentOnly(nd)
  }

  predicate isSink(DataFlow::Node snk) { snk instanceof StackTraceExposure::Sink }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet contents) {
    // Assume all properties of an object sent in a response are exposed, as in `res.json({ error })`.
    isSink(node) and
    contents = DataFlow::ContentSet::anyProperty()
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Taint-tracking for reasoning about exposure of error messages and stack traces. */
module StackTraceExposureExtendedFlow = TaintTracking::Global<StackTraceExposureExtendedConfig>;
