/**
 * Provides a heuristic remote flow source for ASP.NET Core MVC action method
 * parameters in databases where the ASP.NET Core assemblies could not be
 * resolved (for example, `build-mode: none` analysis of loose `.cs` files
 * without a `Microsoft.NET.Sdk.Web` project file).
 *
 * In such databases `Microsoft.AspNetCore.Mvc.ControllerBase` and
 * `Microsoft.AspNetCore.Mvc.Controller` are unknown types and the routing
 * attributes are not extracted, so the standard `MicrosoftAspNetCoreMvcController`
 * class does not recognize the controller. The C# compiler diagnostics that
 * the extractor records for the unresolved base type are used instead.
 */

import csharp
private import semmle.code.csharp.commons.Diagnostics
private import semmle.code.csharp.security.dataflow.flowsources.Remote

/**
 * Holds if `d` reports that the direct base type of `c` named `name`
 * (`Controller` or `ControllerBase`) could not be resolved.
 */
private predicate unresolvedControllerBaseTypeDiagnostic(CompilerError d, Class c) {
  d.getTag() = ["CS0246", "CS0234"] and
  exists(string name, TypeMention baseType |
    name = ["Controller", "ControllerBase"] and
    d.getFullMessage().matches("The type or namespace name '" + name + "' %") and
    baseType.getTarget() = c and
    baseType.getLocation().getFile() = d.getLocation().getFile() and
    baseType.getLocation().getStartLine() = d.getLocation().getStartLine() and
    baseType.getLocation().getStartColumn() = d.getLocation().getStartColumn() and
    baseType.getLocation().getEndLine() = d.getLocation().getEndLine() and
    baseType.getLocation().getEndColumn() = d.getLocation().getEndColumn()
  )
}

/**
 * A class that derives from an unresolved ASP.NET Core MVC controller base
 * type (`Controller` or `ControllerBase`).
 */
class UnresolvedAspNetCoreController extends Class {
  UnresolvedAspNetCoreController() {
    this.fromSource() and
    this instanceof NonNestedType and
    this.isPublic() and
    not this.isAbstract() and
    not this instanceof Generic and
    exists(CompilerError d | unresolvedControllerBaseTypeDiagnostic(d, this))
  }

  /** Gets an action method of this controller. */
  Method getAnActionMethod() {
    result.getDeclaringType() = this and
    result.fromSource() and
    result.isPublic() and
    not result.isStatic() and
    not result.isAbstract() and
    not result instanceof Generic
  }
}

/**
 * A parameter of an action method of a controller whose ASP.NET Core MVC base
 * type could not be resolved, viewed as a source of remote user input.
 */
class UnresolvedAspNetCoreActionMethodParameter extends AspNetCoreRemoteFlowSource,
  DataFlow::ParameterNode
{
  UnresolvedAspNetCoreActionMethodParameter() {
    this.getParameter() = any(UnresolvedAspNetCoreController c).getAnActionMethod().getAParameter()
  }

  override string getSourceType() {
    result = "ASP.NET Core MVC action method parameter (unresolved controller base type)"
  }
}
