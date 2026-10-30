/**
 * @name Android `WebView` that accepts all certificates behind a null check
 * @description An `onReceivedSslError` handler that calls `SslErrorHandler.proceed()` whenever the
 *              handler is not null (for example Kotlin `handler?.proceed()`, `handler!!.proceed()`
 *              or Java `if (handler != null) handler.proceed()`) trusts every certificate,
 *              allowing machine-in-the-middle attacks.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id java/improper-webview-certificate-validation-null-safe
 * @tags security
 *       external/cwe/cwe-295
 */

import java
import semmle.code.java.controlflow.Guards
import semmle.code.java.security.AndroidWebViewCertificateValidationQuery

/**
 * Holds if `v` holds the `SslErrorHandler` parameter of `m`: either the parameter itself or a
 * local variable initialized from it, such as the `tmp0_safe_receiver` variable the Kotlin
 * extractor introduces for a safe call `handler?.proceed()`.
 */
predicate isHandlerVariable(OnReceivedSslErrorMethod m, Variable v) {
  v = m.handlerArg()
  or
  exists(LocalVariableDeclExpr decl |
    decl.getEnclosingCallable() = m and
    decl.getVariable() = v and
    decl.getInit().getUnderlyingExpr().(VarAccess).getVariable() = m.handlerArg()
  )
}

/** Holds if `g` is a null check of the `SslErrorHandler` held in a handler variable of `m`. */
predicate isHandlerNullCheck(OnReceivedSslErrorMethod m, Guard g) {
  exists(EqualityTest eq, Variable v |
    g = eq and
    isHandlerVariable(m, v) and
    eq.getAnOperand() instanceof NullLiteral and
    eq.getAnOperand().getUnderlyingExpr().(VarAccess).getVariable() = v
  )
}

/** A call to `SslErrorHandler.proceed` on the handler of `m`. */
predicate isHandlerProceed(OnReceivedSslErrorMethod m, MethodCall proceed) {
  proceed.getMethod().hasQualifiedName("android.webkit", "SslErrorHandler", "proceed") and
  proceed.getEnclosingCallable() = m and
  exists(Variable v |
    isHandlerVariable(m, v) and
    proceed.getQualifier().getUnderlyingExpr().(VarAccess).getVariable() = v
  )
}

/**
 * Holds if `m` calls `proceed` on every path where the handler is not null: either the call is
 * always executed (for example Kotlin `handler!!.proceed()`), or it is guarded only by null checks
 * of the handler and those checks are always evaluated.
 */
predicate trustsAllCertsWhenNotNull(OnReceivedSslErrorMethod m, MethodCall proceed) {
  isHandlerProceed(m, proceed) and
  (
    proceed.getBasicBlock().postDominates(m.getBody().getBasicBlock())
    or
    exists(Guard nullCheck |
      isHandlerNullCheck(m, nullCheck) and
      nullCheck.controls(proceed.getBasicBlock(), _) and
      nullCheck.getBasicBlock().postDominates(m.getBody().getBasicBlock()) and
      forall(Guard g | g.controls(proceed.getBasicBlock(), _) | isHandlerNullCheck(m, g))
    )
  )
}

from OnReceivedSslErrorMethod m, MethodCall proceed
where
  trustsAllCertsWhenNotNull(m, proceed) and
  // Unconditional `handler.proceed()` calls are reported by `java/improper-webview-certificate-validation`.
  not trustsAllCerts(m)
select proceed,
  "This call accepts all SSL certificates in $@ whenever the error handler is not null.", m,
  m.getName()
