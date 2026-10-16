/**
 * @name Django view changes state on any HTTP method
 * @description A function-based Django view that changes server-side state without
 *              restricting the HTTP method can be triggered by a cross-site GET request
 *              (for example a link or an image tag). Django's CSRF middleware does not
 *              check GET requests.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision medium
 * @id py/custom/django-state-change-on-get
 * @tags security
 *       external/cwe/cwe-352
 */

import python
import semmle.python.ApiGraphs
import semmle.python.frameworks.Django
import DjangoStateChange

/** Holds if `view` is decorated with a Django decorator that restricts the HTTP method. */
predicate restrictsHttpMethod(Function view) {
  view.getADecorator() =
    API::moduleImport("django")
        .getMember("views")
        .getMember("decorators")
        .getMember("http")
        .getMember(["require_POST", "require_http_methods"])
        .getAValueReachableFromSource()
        .asExpr()
  or
  view.getADecorator().(Call).getFunc() =
    API::moduleImport("django")
        .getMember("views")
        .getMember("decorators")
        .getMember("http")
        .getMember("require_http_methods")
        .getAValueReachableFromSource()
        .asExpr()
}

/**
 * Holds if `view` inspects the HTTP method (for example `if request.method == "POST":`)
 * or validates a bound form, either of which normally keeps a GET request from
 * reaching the state change.
 */
predicate checksHttpMethodOrForm(Function view) {
  exists(Attribute a | a.getScope().getEnclosingScope*() = view |
    a.getName() = "method"
    or
    a.getName() = "is_valid"
  )
}

from PrivateDjango::DjangoRouteHandler view, DjangoStateChangingCall call
where
  not view.isMethod() and
  performsStateChange(view, call) and
  not restrictsHttpMethod(view) and
  not checksHttpMethodOrForm(view) and
  not usesNonCookieAuthentication(view) and
  not view.getLocation().getFile().getRelativePath().matches("%test%")
select call,
  "This state-changing '" + call.getOperation() +
    "' operation in $@ runs for any HTTP method, including GET.", view, view.getName()
