/**
 * @name Information exposure through an exception (extended)
 * @description Leaking information about an exception, such as messages and stack traces, or
 *              information about the server environment, to an external user can expose
 *              implementation details that are useful to an attacker for developing a
 *              subsequent exploit.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 5.4
 * @precision medium
 * @id cs/information-exposure-through-exception-extended
 * @tags security
 *       external/cwe/cwe-209
 *       external/cwe/cwe-497
 */

import csharp
import semmle.code.csharp.frameworks.System
import semmle.code.csharp.frameworks.system.web.Http
import semmle.code.csharp.frameworks.system.web.Mvc
import semmle.code.csharp.frameworks.system.web.Services
import semmle.code.csharp.frameworks.microsoft.AspNetCore
import semmle.code.csharp.security.dataflow.flowsinks.Remote
import semmle.code.asp.WebConfig
import ExceptionInformationExposure::PathGraph

/** An expression that is, or is a property of, a `System.Exception`. */
class ExceptionInformationSource extends DataFlow::ExprNode {
  ExceptionInformationSource() {
    exists(Expr expr |
      // Writing an exception directly is bad
      this.asExpr() = expr
      or
      // Writing a property of an exception is bad
      this.asExpr().(PropertyAccess).getQualifier() = expr
    |
      // Expr has type `System.Exception`.
      expr.getType().(RefType).getABaseType*() instanceof SystemExceptionClass and
      // And is not within an exception callable.
      not exists(Callable enclosingCallable | enclosingCallable = expr.getEnclosingCallable() |
        enclosingCallable.getDeclaringType().getABaseType*() instanceof SystemExceptionClass
      )
    )
  }
}

/** An access to a `System.Environment` property that describes the server environment. */
class SystemInformationSource extends DataFlow::ExprNode {
  SystemInformationSource() {
    exists(Property p |
      this.asExpr() = p.getAnAccess() and
      p.getDeclaringType().hasFullyQualifiedName("System", "Environment") and
      p.hasName([
          "CurrentDirectory", "MachineName", "OSVersion", "SystemDirectory", "UserDomainName",
          "UserName"
        ])
    )
  }
}

/** A value returned to the remote caller of an ASMX `[WebMethod]`. */
class WebMethodReturnSink extends DataFlow::ExprNode {
  WebMethodReturnSink() {
    exists(Method m |
      m.getAnAttribute().getType() instanceof SystemWebServicesWebMethodAttributeClass and
      m.canReturn(this.asExpr())
    )
  }
}

/** A value returned from an ASP.NET MVC, Web API or ASP.NET Core controller action method. */
class ActionMethodReturnSink extends DataFlow::ExprNode {
  ActionMethodReturnSink() {
    exists(Method m |
      m = any(MicrosoftAspNetCoreMvcController c).getAnActionMethod() or
      m = any(Controller c).getAnActionMethod() or
      m = any(ApiController c).getAnActionMethod()
    |
      m.canReturn(this.asExpr())
    )
  }
}

/**
 * A response body argument to an ASP.NET Core controller helper method, such as
 * `Ok(value)`, `StatusCode(500, value)` or `Json(data)`, or to an action result constructor.
 */
class ControllerResponseSink extends DataFlow::ExprNode {
  ControllerResponseSink() {
    exists(Call c, Parameter p |
      (
        c.getTarget().getUnboundDeclaration().getDeclaringType() instanceof
          MicrosoftAspNetCoreMvcControllerBaseClass and
        c.getTarget()
            .hasName([
                "Ok", "Json", "Content", "StatusCode", "BadRequest", "NotFound", "Conflict",
                "UnprocessableEntity", "Problem", "ValidationProblem"
              ])
        or
        c instanceof ObjectCreation and
        c.getTarget()
            .getDeclaringType()
            .getABaseType*()
            .hasFullyQualifiedName("Microsoft.AspNetCore.Mvc", ["ObjectResult", "JsonResult"])
      ) and
      p = c.getTarget().getAParameter() and
      p.getName() = ["value", "error", "data", "content", "detail", "title"] and
      this.asExpr() = c.getArgumentForParameter(p)
    )
  }
}

/** A value written to the response by a Razor view, for example `@Model.Error.Message`. */
class RazorWriteSink extends DataFlow::ExprNode {
  RazorWriteSink() {
    exists(MethodCall mc |
      mc.getTarget().hasName("Write") and
      mc.getTarget()
          .getUnboundDeclaration()
          .getDeclaringType()
          .hasFullyQualifiedName(["Microsoft.AspNetCore.Mvc.Razor", "System.Web.WebPages"],
            ["RazorPageBase", "WebPageExecutingBase"]) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

/** A type whose methods handle ASP.NET (System.Web) requests. */
class SystemWebRequestHandlerType extends RefType {
  SystemWebRequestHandlerType() {
    this.getABaseType*().hasFullyQualifiedName("System.Web.UI", "Control") or
    this.getABaseType*().hasFullyQualifiedName("System.Web", ["IHttpHandler", "HttpApplication"])
  }
}

/**
 * The message of an exception thrown by an ASP.NET (System.Web) request handler, when the
 * application disables custom errors. The unhandled exception, including its message, is then
 * rendered to the remote client.
 */
class UnhandledExceptionMessageSink extends DataFlow::ExprNode {
  UnhandledExceptionMessageSink() {
    exists(ThrowElement t, ObjectCreation oc |
      oc = t.getExpr() and
      oc.getType().(RefType).getABaseType*() instanceof SystemExceptionClass and
      this.asExpr() = oc.getAnArgument() and
      t.getEnclosingCallable().getDeclaringType() instanceof SystemWebRequestHandlerType and
      exists(CustomErrorsXmlElement ce | ce.getAttributeValue("mode").toLowerCase() = "off")
    )
  }
}

/**
 * A taint-tracking configuration for reasoning about exception and system information that flows
 * to remote user output.
 */
module ExceptionInformationExposureConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof ExceptionInformationSource or
    source instanceof SystemInformationSource
  }

  predicate isAdditionalFlowStep(DataFlow::Node source, DataFlow::Node sink) {
    sink.asExpr() =
      any(MethodCall mc |
        source.asExpr() = mc.getQualifier() and
        mc.getTarget().hasName("ToString") and
        mc.getQualifier().getType().(RefType).getABaseType*() instanceof SystemExceptionClass
      )
    or
    // Building a JSON document from a tainted value, e.g. `new JObject(new JProperty("e", msg))`.
    exists(ObjectCreation oc |
      oc.getObjectType().getNamespace().getFullName() =
        ["Newtonsoft.Json.Linq", "System.Text.Json.Nodes"] and
      source.asExpr() = oc.getAnArgument() and
      sink.asExpr() = oc
    )
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof RemoteFlowSink or
    sink instanceof WebMethodReturnSink or
    sink instanceof ActionMethodReturnSink or
    sink instanceof ControllerResponseSink or
    sink instanceof RazorWriteSink or
    sink instanceof UnhandledExceptionMessageSink
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    // Objects returned to, or serialized for, the user expose their fields and properties.
    isSink(node) and
    (
      c.isField(_) or
      c.isProperty(_)
    )
  }

  predicate isBarrierIn(DataFlow::Node sanitizer) {
    // Avoid duplicate paths through nested exception values.
    sanitizer.asExpr().getType().(RefType).getABaseType*() instanceof SystemExceptionClass
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/**
 * A taint-tracking module for reasoning about exception and system information that flows to
 * remote user output.
 */
module ExceptionInformationExposure = TaintTracking::Global<ExceptionInformationExposureConfig>;

from
  ExceptionInformationExposure::PathNode source, ExceptionInformationExposure::PathNode sink,
  string kind
where
  ExceptionInformationExposure::flowPath(source, sink) and
  (
    source.getNode() instanceof ExceptionInformationSource and
    kind = "exception information" and
    // Re-throwing (wrapped) exception data is only a problem when it carries system information.
    not sink.getNode() instanceof UnhandledExceptionMessageSink
    or
    source.getNode() instanceof SystemInformationSource and
    kind = "system information"
  )
select sink.getNode(), source, sink, "This information exposed to the user depends on $@.",
  source.getNode(), kind
