/**
 * @name Rails production configuration does not enforce SSL
 * @description A Rails production environment that does not enable `config.force_ssl`
 *              accepts plain HTTP requests, does not send HSTS headers and does not mark
 *              cookies as `Secure`, so credentials and session cookies may be transmitted
 *              in cleartext.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.9
 * @precision medium
 * @id rb/rails-force-ssl-disabled
 * @tags security
 *       external/cwe/cwe-319
 *       external/cwe/cwe-614
 */

import codeql.ruby.AST

/** Holds if `f` is a `config/environments/<name>.rb` file of the Rails application in `root`. */
predicate isEnvironmentFile(File f, Folder root, string name) {
  f.getExtension() = "rb" and
  name = f.getStem() and
  f.getParentContainer().getBaseName() = "environments" and
  f.getParentContainer().getParentContainer().getBaseName() = "config" and
  root = f.getParentContainer().getParentContainer().getParentContainer()
}

/** Holds if `f` is the production environment file of the Rails application in `root`. */
predicate isProductionFile(File f, Folder root) { isEnvironmentFile(f, root, "production") }

/**
 * Holds if `n` is in the application's own `config/`, `app/` or `lib/` code in `root`
 * (excluding, for example, vendored gems and tests) and may affect its production
 * environment (that is, it is not in a non-production environment file).
 */
predicate appliesToProduction(AstNode n, Folder root) {
  exists(Folder top |
    top.getParentContainer() = root and
    top.getBaseName() = ["config", "app", "lib"] and
    n.getFile().getParentContainer+() = top
  ) and
  not exists(string env | isEnvironmentFile(n.getFile(), _, env) and env != "production")
}

/** An assignment of the form `config.force_ssl = value`. */
class ForceSslAssignment extends AssignExpr {
  ForceSslAssignment() {
    exists(MethodCall lhs | lhs = this.getLeftOperand() |
      lhs.getMethodName() = "force_ssl" and
      lhs.getReceiver().(MethodCall).getMethodName() = "config"
    )
  }

  /** Holds if this assignment explicitly disables `force_ssl`. */
  predicate isDisabled() {
    this.getRightOperand().getConstantValue().getBoolean() = false
    or
    this.getRightOperand().getConstantValue().isNil()
  }
}

/**
 * A construct (other than `config.force_ssl`) that enforces HTTPS for the application:
 * an unconditional `force_ssl` call in an application controller or an SSL-enforcing
 * Rack middleware reference.
 */
class AlternativeSslEnforcement extends AstNode {
  AlternativeSslEnforcement() {
    exists(MethodCall c | c = this |
      c.getMethodName() = "force_ssl" and
      c.getNumberOfArguments() = 0 and
      (not exists(c.getReceiver()) or c.getReceiver() instanceof SelfVariableAccess) and
      c.getEnclosingModule().getModule().getQualifiedName() =
        ["ApplicationController", "ActionController::Base"]
    )
    or
    exists(ConstantReadAccess c | c = this |
      (
        c.getName() = "SSL" and
        c.getScopeExpr().(ConstantAccess).getName() = ["Rack", "ActionDispatch"]
        or
        c.getName() = "SslEnforcer" and
        c.getScopeExpr().(ConstantAccess).getName() = "Rack"
      ) and
      isAddedMiddleware(c)
    )
  }
}

/**
 * Holds if `e` is the middleware added by a `middleware.use`, `middleware.unshift`,
 * `middleware.insert_before` or `middleware.insert_after` call (not, for example, the
 * middleware removed by `middleware.delete` or the position anchor of `insert_before`).
 */
predicate isAddedMiddleware(Expr e) {
  exists(MethodCall add |
    add.getReceiver().(MethodCall).getMethodName() = "middleware" and
    (
      add.getMethodName() = ["use", "unshift"] and e = add.getArgument(0)
      or
      add.getMethodName() = ["insert", "insert_before", "insert_after"] and
      e = add.getArgument(1)
    )
  )
}

/** Holds if the production environment file contains a `config.force_ssl` assignment. */
predicate hasProductionForceSslAssignment(Folder root) {
  exists(ForceSslAssignment a | isProductionFile(a.getFile(), root))
}

/** Holds if the Rails application in `root` enforces SSL in production by some means. */
predicate hasSslEnforcement(Folder root) {
  exists(ForceSslAssignment a |
    appliesToProduction(a, root) and
    not a.isDisabled() and
    (
      isProductionFile(a.getFile(), root)
      or
      not hasProductionForceSslAssignment(root)
    )
  )
  or
  exists(AlternativeSslEnforcement e | appliesToProduction(e, root))
}

/** A `Rails.application.configure do ... end` or `<App>::Application.configure do ... end` call. */
class RailsConfigureCall extends MethodCall {
  RailsConfigureCall() {
    this.getMethodName() = "configure" and
    exists(this.getBlock()) and
    (
      exists(MethodCall app | app = this.getReceiver() |
        app.getMethodName() = "application" and
        app.getReceiver().(ConstantReadAccess).getName() = "Rails"
      )
      or
      this.getReceiver().(ConstantReadAccess).getName() = "Application"
    )
  }
}

from AstNode alert, string message, Folder root
where
  not hasSslEnforcement(root) and
  (
    exists(ForceSslAssignment a |
      a = alert and
      isProductionFile(a.getFile(), root) and
      a.isDisabled() and
      message =
        "SSL enforcement is explicitly disabled for production, so credentials and session cookies may be sent over cleartext HTTP."
    )
    or
    exists(RailsConfigureCall c |
      c = alert and
      isProductionFile(c.getFile(), root) and
      not exists(ForceSslAssignment a | a.getFile() = c.getFile()) and
      message =
        "Production configuration does not enable 'config.force_ssl', so credentials and session cookies may be sent over cleartext HTTP."
    )
  )
select alert, message
