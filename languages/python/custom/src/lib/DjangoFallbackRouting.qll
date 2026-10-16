/**
 * Provides fallback resolution of Django function-based views that are routed as
 * `module.view` (for example `url(r"^...$", views.upload)` after
 * `from taskManager import views`) when normal module resolution fails.
 *
 * Module resolution can fail when the project is checked out into a folder whose
 * name contains a dot, such as `django.nV`: `Folder.getStem()` is then `django`,
 * the folder is treated as a namespace package named `django`, and every module
 * inside it gets a `django.` prefix (for example `django.taskManager.views`), so
 * `from taskManager import views` no longer resolves.
 *
 * Importing this library adds the parameters of such views as remote flow sources.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.frameworks.Django

/** Provides fallback resolution of Django function-based views. */
module DjangoFallbackRouting {
  /**
   * Gets the dotted name of the module bound to `n` by `from P import M` or by
   * `import P.M as n`.
   */
  private string importedModuleName(Name n) {
    exists(Alias a | a.getAsname().(Name).getVariable() = n.getVariable() |
      exists(ImportMember im | a.getValue() = im |
        result = im.getModule().(ImportExpr).getImportedModuleName() + "." + im.getName()
      )
      or
      result = a.getValue().(ImportExpr).getImportedModuleName() and
      // `import P.M` (without `as`) binds `P`, not `P.M`
      not n.getId() + "." = result.prefix(n.getId().length() + 1)
    )
  }

  /** Holds if the module `m` is named `name`, possibly with an additional package prefix. */
  bindingset[name]
  private predicate moduleNameMatches(Module m, string name) {
    exists(string actual | actual = m.getName() |
      actual = name
      or
      actual.length() > name.length() and
      actual.suffix(actual.length() - name.length() - 1) = "." + name
    )
  }

  /**
   * Gets a function-based view that the route `setup` refers to as `module.view`,
   * when the standard Django modeling cannot resolve any request handler for it.
   */
  Function fallbackViewFunction(PrivateDjango::DjangoRouteSetup setup) {
    not exists(setup.getARequestHandler()) and
    exists(Attribute attr |
      setup.getViewArg().asExpr() = attr and
      result.getName() = attr.getName() and
      not result.isMethod() and
      moduleNameMatches(result.getScope(), importedModuleName(attr.getObject()))
    )
  }

  /** A parameter of a Django view that is only resolved by `fallbackViewFunction`. */
  abstract class FallbackViewParameter extends RemoteFlowSource::Range, DataFlow::ParameterNode { }

  /** The `request` parameter of a fallback-resolved Django view. */
  class FallbackRequestParameter extends FallbackViewParameter,
    PrivateDjango::DjangoImpl::DjangoHttp::Request::HttpRequest::InstanceSource
  {
    FallbackRequestParameter() { this.getParameter() = fallbackViewFunction(_).getArg(0) }

    override string getSourceType() { result = "django.http.request.HttpRequest" }
  }

  /** A routed parameter (any parameter after `request`) of a fallback-resolved Django view. */
  class FallbackRoutedParameter extends FallbackViewParameter {
    FallbackRoutedParameter() {
      exists(Function f | f = fallbackViewFunction(_) |
        this.getParameter() = f.getArg(any(int i | i > 0))
        or
        this.getParameter() = f.getArgByName(_) and
        not this.getParameter() = f.getArg(0)
      )
    }

    override string getSourceType() { result = "django routed param" }
  }
}
