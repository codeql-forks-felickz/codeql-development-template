/**
 * @name Information exposure through an exception (additional sinks)
 * @description Leaking information about an exception, such as messages, stack traces or the
 *              exception object itself, through an `http.server` response stream or a server-side
 *              template can expose implementation details that are useful to an attacker.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.4
 * @precision medium
 * @id py/error-message-exposure
 * @tags security
 *       external/cwe/cwe-209
 *       external/cwe/cwe-497
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
import semmle.python.security.dataflow.StackTraceExposureCustomizations

/**
 * Gets a reference to a `BaseHTTPRequestHandler` class (or one of its standard library
 * subclasses), or any subclass of these.
 */
API::Node httpRequestHandlerClass() {
  result =
    [
      API::moduleImport("http")
          .getMember("server")
          .getMember(["BaseHTTPRequestHandler", "SimpleHTTPRequestHandler", "CGIHTTPRequestHandler"]),
      API::moduleImport("BaseHTTPServer").getMember("BaseHTTPRequestHandler"),
      API::moduleImport("SimpleHTTPServer").getMember("SimpleHTTPRequestHandler"),
      API::moduleImport("CGIHTTPServer").getMember("CGIHTTPRequestHandler")
    ].getASubclass*()
}

/**
 * A parameter that, judging by its name or type annotation, receives an exception object.
 *
 * Error-handling callbacks are often invoked through dynamic dispatch (for example looked up
 * from a dictionary of status-code handlers in a middleware), so the flow from the `except`
 * clause to the callback cannot always be resolved by the call graph.
 */
class ExceptionParameter extends DataFlow::ParameterNode {
  ExceptionParameter() {
    exists(Parameter p | p = this.getParameter() |
      p.getName().regexpMatch("(?i)ex|exc|exception|exc_info")
      or
      exists(Expr ann | ann = p.getAnnotation() |
        ann.(Name).getId().regexpMatch(".*(Exception|Error)")
        or
        ann.(Attribute).getName().regexpMatch(".*(Exception|Error)")
      )
    )
  }
}

/** A data-flow sink where exception information is exposed to an external user. */
abstract class ErrorMessageExposureSink extends DataFlow::Node {
  /** Gets a description of the kind of sink. */
  abstract string getSinkKind();
}

/**
 * The data written to the response stream (`self.wfile`) of a `BaseHTTPRequestHandler`,
 * which is sent directly to the HTTP client.
 */
class HttpRequestHandlerWfileWrite extends ErrorMessageExposureSink {
  HttpRequestHandlerWfileWrite() {
    exists(DataFlow::MethodCallNode write, DataFlow::AttrRead wfile |
      write.calls(wfile, "write") and
      wfile.getAttributeName() = "wfile" and
      this = write.getArg(0)
    |
      wfile.getObject() =
        httpRequestHandlerClass().getAMember().getSelfParameter().getAValueReachableFromSource()
      or
      // Also match `self.wfile` syntactically, since local flow from the `self` parameter
      // is not always available (for example after a statement containing a conditional
      // expression with a short-circuiting condition).
      exists(Class cls |
        cls.getParent() = httpRequestHandlerClass().asSource().asExpr() and
        wfile.getObject().asExpr().(Name).getVariable() =
          cls.getAMethod().getArg(0).(Name).getVariable()
      )
    )
  }

  override string getSinkKind() { result = "HTTP response stream" }
}

/**
 * A value passed in the context of a server-side template rendering call. The rendered
 * template is returned to the HTTP client, so exception objects or stack traces passed to it
 * may be exposed (for example `{{ error }}` or `{{ error.__dict__ }}`).
 */
class TemplateContextSink extends ErrorMessageExposureSink {
  TemplateContextSink() {
    // aiohttp_jinja2.render_template(template_name, request, context, ...)
    this =
      API::moduleImport("aiohttp_jinja2")
          .getMember([
              "render_template", "render_string", "render_template_async", "render_string_async"
            ])
          .getACall()
          .getParameter(2, "context")
          .asSink()
    or
    // flask.render_template(template_name_or_list, **context)
    exists(API::CallNode call |
      call = API::moduleImport("flask").getMember(["render_template", "stream_template"]).getACall()
    |
      this = call.getArgByName(_)
      or
      this = call.getKwargs()
    )
    or
    // django.shortcuts.render(request, template_name, context=None, ...)
    this =
      API::moduleImport("django")
          .getMember("shortcuts")
          .getMember("render")
          .getACall()
          .getParameter(2, "context")
          .asSink()
  }

  override string getSinkKind() { result = "template context" }
}

private module ErrorMessageExposureConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof StackTraceExposure::Source
    or
    source instanceof ExceptionParameter
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof ErrorMessageExposureSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof StackTraceExposure::Sanitizer }

  // A stack trace is accessible as the `__traceback__` attribute of a caught exception.
  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(DataFlow::AttrRead attr | attr.getAttributeName() = "__traceback__" |
      nodeFrom = attr.getObject() and
      nodeTo = attr
    )
  }
}

module ErrorMessageExposureFlow = TaintTracking::Global<ErrorMessageExposureConfig>;

import ErrorMessageExposureFlow::PathGraph

from
  ErrorMessageExposureFlow::PathNode source, ErrorMessageExposureFlow::PathNode sink,
  ErrorMessageExposureSink sinkNode
where
  ErrorMessageExposureFlow::flowPath(source, sink) and
  sinkNode = sink.getNode()
select sink.getNode(), source, sink,
  "$@ flows to this " + sinkNode.getSinkKind() + " and may be exposed to an external user.",
  source.getNode(), "Exception information"
