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

private predicate isMethodSequenceWithoutGet(Expr methods) {
  (
    exists(List list, StringLiteral method |
      methods = list and
      method = list.getAnElt() and
      method.getText().toUpperCase() != "GET"
    )
    or
    exists(Tuple tuple, StringLiteral method |
      methods = tuple and
      method = tuple.getAnElt() and
      method.getText().toUpperCase() != "GET"
    )
  ) and
  forall(Expr method |
    method = methods.(List).getAnElt() or method = methods.(Tuple).getAnElt()
  |
    method instanceof StringLiteral and method.(StringLiteral).getText().toUpperCase() != "GET"
  )
}

private predicate isMethodSequenceWithGet(Expr methods) {
  exists(List list, StringLiteral method |
    methods = list and
    method = list.getAnElt() and
    method.getText().toUpperCase() = "GET"
  )
  or
  exists(Tuple tuple, StringLiteral method |
    methods = tuple and
    method = tuple.getAnElt() and
    method.getText().toUpperCase() = "GET"
  )
}

/** Holds if `view` is decorated with a method restriction that excludes GET. */
predicate restrictsHttpMethod(Function view) {
  view.getADecorator() =
    API::moduleImport("django")
        .getMember("views")
        .getMember("decorators")
        .getMember("http")
        .getMember("require_POST")
        .getAValueReachableFromSource()
        .asExpr()
  or
  exists(Call decorator |
    view.getADecorator() = decorator and
    decorator.getFunc() =
      API::moduleImport("django")
          .getMember("views")
          .getMember("decorators")
          .getMember("http")
          .getMember("require_http_methods")
          .getAValueReachableFromSource()
          .asExpr() and
    isMethodSequenceWithoutGet(decorator.getArg(0))
  )
}

private predicate requestMethodAttribute(Function view, Attribute method) {
  method.getName() = "method" and
  method.getObject().(Name).getVariable() = view.getArg(0).(Name).getVariable()
}

private predicate methodTestExcludesGet(Expr test, boolean branch, Function view) {
  exists(Compare comparison, Attribute method, Cmpop op, StringLiteral value |
    test = comparison and
    comparison.compares(method, op, value) and
    requestMethodAttribute(view, method) and
    (
      op instanceof Eq and
      (
        branch = true and value.getText().toUpperCase() != "GET"
        or
        branch = false and value.getText().toUpperCase() = "GET"
      )
      or
      op instanceof NotEq and
      (
        branch = true and value.getText().toUpperCase() = "GET"
        or
        branch = false and value.getText().toUpperCase() != "GET"
      )
    )
  )
  or
  exists(Compare comparison, Attribute method, Cmpop op, Expr methods |
    test = comparison and
    comparison.compares(method, op, methods) and
    requestMethodAttribute(view, method) and
    isMethodSequenceWithoutGet(methods) and
    (
      op instanceof In and branch = true
      or
      op instanceof NotIn and branch = false
    )
  )
  or
  exists(Compare comparison, Attribute method, Cmpop op, Expr methods |
    test = comparison and
    comparison.compares(method, op, methods) and
    requestMethodAttribute(view, method) and
    isMethodSequenceWithGet(methods) and
    (
      op instanceof In and branch = false
      or
      op instanceof NotIn and branch = true
    )
  )
  or
  exists(UnaryExpr negation, Not notOp |
    test = negation and
    negation.getOp() = notOp and
    methodTestExcludesGet(negation.getOperand(), branch.booleanNot(), view)
  )
}

private predicate formValidationAllowsMutation(Expr test, boolean branch) {
  exists(Call validation, Attribute method |
    validation.getFunc() = method and method.getName() = "is_valid" and
    (
      test = validation and branch = true
      or
      exists(UnaryExpr negation, Not notOp |
        test = negation and negation.getOp() = notOp and
        negation.getOperand() = validation and branch = false
      )
    )
  )
}

/**
 * Holds if a condition controlling `call` proves that a GET request cannot reach it.
 */
predicate controlsMutationAwayFromGet(Function view, DjangoStateChangingCall call) {
  exists(ConditionBlock condition, Expr test, boolean branch |
    condition.getLastNode().getNode() = test and
    condition.controls(call.asCfgNode().getBasicBlock(), branch) and
    (
      methodTestExcludesGet(test, branch, view)
      or
      formValidationAllowsMutation(test, branch)
    )
  )
}

from PrivateDjango::DjangoRouteHandler view, DjangoStateChangingCall call
where
  not view.isMethod() and
  performsStateChange(view, call) and
  not restrictsHttpMethod(view) and
  not controlsMutationAwayFromGet(view, call) and
  not usesNonCookieAuthentication(view) and
  not view.getLocation().getFile().getRelativePath().matches("%test%")
select call,
  "This state-changing '" + call.getOperation() +
    "' operation in $@ runs for any HTTP method, including GET.", view, view.getName()
