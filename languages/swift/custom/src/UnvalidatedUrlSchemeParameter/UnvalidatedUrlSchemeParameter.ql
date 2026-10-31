/**
 * @name Unvalidated custom URL scheme parameter
 * @description Using data from a custom URL scheme (deep link) to drive user-visible
 *              messages or actions without validating it allows other apps and web
 *              pages to trigger those actions with attacker-chosen values.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id swift/unvalidated-url-scheme-parameter
 * @tags security
 *       external/cwe/cwe-020
 *       external/cwe/cwe-939
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.controlflow.BasicBlocks
import codeql.swift.controlflow.ControlFlowGraph
private import codeql.swift.generated.ParentChild
import UnvalidatedUrlSchemeParameterFlow::PathGraph

/**
 * A parameter of a `UIApplicationDelegate` or `UISceneDelegate` method that iOS
 * calls with the URL (or URL contexts) used to open the app through a custom URL
 * scheme.
 */
class CustomUrlSchemeSource extends DataFlow::Node {
  CustomUrlSchemeSource() {
    exists(Method m, string protocol, string name, int i |
      m.getEnclosingDecl().asNominalTypeDecl().getABaseTypeDecl*().(ProtocolDecl).getName() =
        protocol and
      m.getName() = name and
      this.asParameter() = m.getParam(i)
    |
      protocol = "UIApplicationDelegate" and
      name =
        [
          "application(_:open:options:)", "application(_:handleOpen:)",
          "application(_:open:sourceApplication:annotation:)"
        ] and
      i = 1
      or
      protocol = "UISceneDelegate" and
      name = "scene(_:openURLContexts:)" and
      i = 1
      or
      protocol = "UISceneDelegate" and
      name = "scene(_:willConnectTo:options:)" and
      i = 2
    )
  }
}

/**
 * A value that is shown to the user or that drives an action on the user's behalf.
 */
class UrlSchemeParameterSink extends DataFlow::Node {
  string kind;

  UrlSchemeParameterSink() {
    // `UIAlertController(title:message:preferredStyle:)`
    exists(CallExpr call, Initializer init |
      call.getStaticTarget() = init and
      init.getEnclosingDecl().asNominalTypeDecl().getName() = "UIAlertController" and
      init.getName() = "init(title:message:preferredStyle:)" and
      this.asExpr() = call.getArgument([0, 1]).getExpr() and
      kind = "an alert"
    )
    or
    // `MFMessageComposeViewController.recipients` / `.body` and
    // `MFMailComposeViewController.setToRecipients(_:)` and similar.
    exists(AssignExpr assign, MemberRefExpr ref |
      assign.getDest() = ref and
      not assign.getEnclosingFunction() instanceof Accessor and
      ref.getMember().(VarDecl).getEnclosingDecl().asNominalTypeDecl().getName() =
        "MFMessageComposeViewController" and
      ref.getMember().(VarDecl).getName() = ["recipients", "body", "subject"] and
      this.asExpr() = assign.getSource() and
      kind = "a message composer"
    )
    or
    exists(CallExpr call, Method m |
      call.getStaticTarget() = m and
      m.getEnclosingDecl().asNominalTypeDecl().getName() = "MFMailComposeViewController" and
      m.getName() =
        [
          "setToRecipients(_:)", "setCcRecipients(_:)", "setBccRecipients(_:)", "setSubject(_:)",
          "setMessageBody(_:isHTML:)"
        ] and
      this.asExpr() = call.getArgument(0).getExpr() and
      kind = "a mail composer"
    )
    or
    // `UIApplication.open(_:options:completionHandler:)` / `openURL(_:)`
    exists(CallExpr call, Method m |
      call.getStaticTarget() = m and
      m.getEnclosingDecl().asNominalTypeDecl().getName() = "UIApplication" and
      m.getName() = ["open(_:options:completionHandler:)", "openURL(_:)"] and
      this.asExpr() = call.getArgument(0).getExpr() and
      kind = "a URL opened by the app"
    )
  }

  /** Gets a description of what this sink is. */
  string getKind() { result = kind }
}

/** Gets `e` with any optional bindings and force unwraps removed. */
private Expr stripped(Expr e) {
  result = e and
  not result instanceof BindOptionalExpr and
  not result instanceof ForceValueExpr
  or
  result = stripped(e.(BindOptionalExpr).getSubExpr())
  or
  result = stripped(e.(ForceValueExpr).getSubExpr())
}

/**
 * Holds if `check` is a call or comparison, appearing in a branch condition,
 * that directly inspects the value of `v` (for example `isValid(v)`,
 * `allowed.contains(v)`, `v.allSatisfy(...)` or `v == "expected"`).
 */
private predicate validatesVariable(Expr check, VarDecl v) {
  exists(Expr operand |
    operand.(DeclRefExpr).getDecl() = v and
    (
      operand = stripped(check.(CallExpr).getAnArgument().getExpr())
      or
      operand = stripped(check.(CallExpr).getQualifier())
      or
      operand = stripped(check.(BinaryExpr).getAnOperand()) and
      check.(BinaryExpr).getStaticTarget().getName() = ["==(_:_:)", "!=(_:_:)", "~=(_:_:)"]
    )
  )
}

/**
 * A read of a variable whose value has been validated by an enclosing
 * `if`/`guard`/`while` condition.
 */
class ValidatedVariableBarrier extends DataFlow::Node {
  ValidatedVariableBarrier() {
    exists(ConditionBlock bb, Expr cond, Expr check, VarDecl v, boolean branch |
      cond = bb.getLastNode().getNode().asAstNode() and
      cond = getImmediateParent*(check) and
      validatesVariable(check, v) and
      this.asExpr().(DeclRefExpr).getDecl() = v and
      bb.edgeDominates(this.getCfgNode().getBasicBlock(),
        any(BooleanSuccessor s | s.getValue() = branch))
    )
  }
}

module UnvalidatedUrlSchemeParameterConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof CustomUrlSchemeSource }

  predicate isSink(DataFlow::Node node) { node instanceof UrlSchemeParameterSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof ValidatedVariableBarrier }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // `URLComponents(url:resolvingAgainstBaseURL:)` and `URLComponents(string:)`
    exists(CallExpr call, Initializer init |
      call.getStaticTarget() = init and
      init.getEnclosingDecl().asNominalTypeDecl().getName() = "URLComponents" and
      pred.asExpr() = call.getArgument(0).getExpr() and
      succ.asExpr() = call
    )
    or
    // Members of `URLComponents` and `URLQueryItem`, for example `queryItems` and `value`.
    exists(MemberRefExpr ref |
      ref.getMember().(VarDecl).getEnclosingDecl().asNominalTypeDecl().getName() =
        ["URLComponents", "URLQueryItem"] and
      pred.asExpr() = ref.getBase() and
      succ.asExpr() = ref
    )
    or
    // Iterating over a tainted collection, for example `for context in URLContexts`.
    exists(ForEachStmt for |
      pred.asExpr() = [for.getSequence(), for.getSequence().(CallExpr).getQualifier()] and
      succ.asPattern() = for.getPattern()
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UnvalidatedUrlSchemeParameterFlow =
  TaintTracking::Global<UnvalidatedUrlSchemeParameterConfig>;

from
  UnvalidatedUrlSchemeParameterFlow::PathNode source,
  UnvalidatedUrlSchemeParameterFlow::PathNode sink
where UnvalidatedUrlSchemeParameterFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This value from a $@ reaches " + sink.getNode().(UrlSchemeParameterSink).getKind() +
    " without being validated.", source.getNode(), "custom URL scheme parameter"
