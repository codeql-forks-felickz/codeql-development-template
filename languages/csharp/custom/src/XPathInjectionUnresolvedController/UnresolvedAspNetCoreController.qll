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
 * Holds if `d` is a compiler error reporting that the ASP.NET Core MVC
 * controller base type `name` (`Controller` or `ControllerBase`) could not be
 * resolved.
 */
private predicate unresolvedControllerBaseTypeDiagnostic(CompilerError d, string name) {
  d.getTag() = ["CS0246", "CS0234"] and
  name = ["Controller", "ControllerBase"] and
  d.getFullMessage().matches("The type or namespace name '" + name + "' %")
}

/** Gets the first line of a source member declared in `c`. */
private int firstMemberLine(Class c) {
  result =
    min(Member m |
      m.getDeclaringType() = c and
      m.fromSource() and
      not m.isCompilerGenerated()
    |
      m.getLocation().getStartLine()
    )
}

/**
 * Holds if `d` is located in the header of the declaration of `c`, that is,
 * after the class name and before the first member of `c`.
 */
bindingset[c]
pragma[inline_late]
private predicate inClassHeader(CompilerError d, Class c) {
  exists(Location dl, Location cl |
    dl = d.getLocation() and
    cl = c.getLocation() and
    dl.getFile() = cl.getFile() and
    dl.getStartLine() < firstMemberLine(c) and
    (
      dl.getStartLine() > cl.getStartLine()
      or
      dl.getStartLine() = cl.getStartLine() and dl.getStartColumn() > cl.getEndColumn()
    )
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
    exists(CompilerError d |
      unresolvedControllerBaseTypeDiagnostic(d, _) and
      inClassHeader(d, this)
    )
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
