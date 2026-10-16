/**
 * @name Dynamically registered broadcast receiver without protection
 * @description A broadcast receiver registered at runtime for a custom action, without a
 *              broadcast permission and without `RECEIVER_NOT_EXPORTED`, receives intents
 *              sent by any application on the device.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.2
 * @precision high
 * @id java/android/unprotected-dynamic-broadcast-receiver
 * @tags security
 *       external/cwe/cwe-925
 *       external/cwe/cwe-926
 */

import java
import semmle.code.java.dataflow.DataFlow

/** The value of `Context.RECEIVER_NOT_EXPORTED` and `ContextCompat.RECEIVER_NOT_EXPORTED`. */
int receiverNotExported() { result = 4 }

/**
 * A method that registers a broadcast receiver: `Context.registerReceiver` (or an override of
 * it) or `ContextCompat.registerReceiver`.
 */
class RegisterReceiverMethod extends Method {
  RegisterReceiverMethod() {
    this.getSourceDeclaration()
        .overridesOrInstantiates*(any(Method m |
            m.hasQualifiedName("android.content", "Context", "registerReceiver")
          ))
    or
    this.hasQualifiedName("androidx.core.content", "ContextCompat", "registerReceiver")
  }

  /** Gets the index of the parameter of type `name`. */
  int getParameterIndex(string name) {
    this.getParameterType(result).(RefType).hasQualifiedName(_, name)
    or
    this.getParameterType(result).(PrimitiveType).hasName(name)
  }
}

/** Gets a custom (non-`android.`) action string that `filter` is configured with. */
string getACustomAction(Expr filter) {
  exists(ClassInstanceExpr newFilter |
    newFilter.getConstructedType().hasQualifiedName("android.content", "IntentFilter") and
    DataFlow::localExprFlow(newFilter, filter)
  |
    result = newFilter.getArgument(0).(CompileTimeConstantExpr).getStringValue()
    or
    exists(MethodCall addAction |
      addAction.getMethod().hasQualifiedName("android.content", "IntentFilter", "addAction") and
      DataFlow::localExprFlow(newFilter, addAction.getQualifier()) and
      result = addAction.getArgument(0).(CompileTimeConstantExpr).getStringValue()
    )
  ) and
  not result.matches("android.%")
}

from MethodCall call, RegisterReceiverMethod m, string action
where
  m = call.getMethod() and
  not call.getArgument(m.getParameterIndex("BroadcastReceiver")) instanceof NullLiteral and
  action = min(getACustomAction(call.getArgument(m.getParameterIndex("IntentFilter")))) and
  // No broadcast permission is required from senders.
  forall(int i | i = m.getParameterIndex("String") | call.getArgument(i) instanceof NullLiteral) and
  // The flags, if any, are known and do not include `RECEIVER_NOT_EXPORTED`.
  forall(int i | i = m.getParameterIndex("int") |
    exists(CompileTimeConstantExpr flags | DataFlow::localExprFlow(flags, call.getArgument(i))) and
    not exists(CompileTimeConstantExpr flags |
      DataFlow::localExprFlow(flags, call.getArgument(i)) and
      flags.getIntValue().bitAnd(receiverNotExported()) = receiverNotExported()
    )
  )
select call,
  "This broadcast receiver is registered for the custom action '" + action +
    "' without a broadcast permission or RECEIVER_NOT_EXPORTED, so any application can send it intents."
