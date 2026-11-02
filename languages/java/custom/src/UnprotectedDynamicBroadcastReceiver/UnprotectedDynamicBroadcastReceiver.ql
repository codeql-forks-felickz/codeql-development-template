/**
 * @name Unprotected dynamically registered broadcast receiver
 * @description Registering a broadcast receiver for an application-defined action
 *              without a broadcast permission or `RECEIVER_NOT_EXPORTED` lets any
 *              other application send it arbitrary intents.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id java/android/unprotected-dynamic-broadcast-receiver
 * @tags security
 *       external/cwe/cwe-925
 *       external/cwe/cwe-926
 */

import java
import semmle.code.java.dataflow.DataFlow

/** The class `android.content.IntentFilter`. */
class TypeIntentFilter extends Class {
  TypeIntentFilter() { this.hasQualifiedName("android.content", "IntentFilter") }
}

/** A call to `Context.registerReceiver` or `ContextCompat.registerReceiver`. */
class RegisterReceiverCall extends MethodCall {
  RegisterReceiverCall() {
    exists(Method m | m = this.getMethod() and m.hasName("registerReceiver") |
      m.getDeclaringType().getASupertype*().hasQualifiedName("android.content", "Context") or
      m.getDeclaringType().hasQualifiedName("androidx.core.content", "ContextCompat")
    )
  }

  /** Gets the argument of this call at a parameter of type `t`. */
  private Expr getArgumentOfType(Type t) {
    exists(int i | result = this.getArgument(i) and t = this.getMethod().getParameterType(i))
  }

  /** Gets the `IntentFilter` argument. */
  Expr getFilterArgument() { result = this.getArgumentOfType(any(TypeIntentFilter t)) }

  /** Gets the broadcast permission argument, if any. */
  Expr getPermissionArgument() { result = this.getArgumentOfType(any(TypeString t)) }

  /** Gets the flags argument, if any. */
  Expr getFlagsArgument() { result = this.getArgumentOfType(any(IntegralType t)) }

  /** Holds if this call requires senders to hold a broadcast permission. */
  predicate hasPermission() {
    exists(Expr perm | perm = this.getPermissionArgument() | not perm instanceof NullLiteral)
  }

  /** Holds if this call registers the receiver with the `RECEIVER_NOT_EXPORTED` flag. */
  predicate isNotExported() {
    exists(Expr flags | flags = this.getFlagsArgument() |
      exists(FieldAccess fa |
        fa.getParent*() = flags and fa.getField().hasName("RECEIVER_NOT_EXPORTED")
      )
      or
      flags.(CompileTimeConstantExpr).getIntValue().bitAnd(4) != 0
    )
  }
}

/** Holds if `action` is an action that `call` registers its receiver for. */
predicate registeredAction(RegisterReceiverCall call, string action) {
  exists(ClassInstanceExpr newFilter |
    newFilter.getConstructedType() instanceof TypeIntentFilter and
    DataFlow::localExprFlow(newFilter, call.getFilterArgument())
  |
    action = newFilter.getArgument(0).(CompileTimeConstantExpr).getStringValue()
    or
    exists(MethodCall addAction |
      addAction.getMethod().hasName("addAction") and
      addAction.getMethod().getDeclaringType() instanceof TypeIntentFilter and
      DataFlow::localExprFlow(newFilter, addAction.getQualifier()) and
      action = addAction.getArgument(0).(CompileTimeConstantExpr).getStringValue()
    )
  )
}

/**
 * Holds if `action` is an application-defined action, as opposed to a system
 * broadcast action (which only the system can send).
 */
bindingset[action]
predicate isCustomAction(string action) { not action.matches("android.%") }

from RegisterReceiverCall call, string actions
where
  not call.hasPermission() and
  not call.isNotExported() and
  actions =
    strictconcat(string action |
      registeredAction(call, action) and isCustomAction(action)
    |
      action, "', '"
    )
select call,
  "This broadcast receiver is registered for action '" + actions +
    "' without a broadcast permission or RECEIVER_NOT_EXPORTED, so any application can send it intents."
