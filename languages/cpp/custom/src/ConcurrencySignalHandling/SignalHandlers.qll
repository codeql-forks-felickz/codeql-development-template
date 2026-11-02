/**
 * Provides classes and predicates for reasoning about POSIX/C signal handlers.
 */

import cpp

/**
 * A call to a function that installs a signal handler given directly as an
 * argument, such as `signal(SIGINT, handler)`.
 */
class SignalFunctionCall extends FunctionCall {
  SignalFunctionCall() {
    this.getTarget().hasGlobalOrStdName(["signal", "bsd_signal", "sysv_signal", "sigset"])
  }

  /** Gets the expression for the signal number. */
  Expr getSignalExpr() { result = this.getArgument(0) }

  /** Gets the expression for the handler (a function or `SIG_DFL`/`SIG_IGN`). */
  Expr getHandlerExpr() { result = this.getArgument(1) }
}

/** A call to `sigaction`. */
class SigactionCall extends FunctionCall {
  SigactionCall() { this.getTarget().hasGlobalOrStdName("sigaction") }

  /** Gets the expression for the signal number. */
  Expr getSignalExpr() { result = this.getArgument(0) }
}

/** A field of `struct sigaction` that holds a handler function. */
private class SigactionHandlerField extends Field {
  SigactionHandlerField() {
    this.hasName(["sa_handler", "sa_sigaction"]) and
    // glibc declares these fields in a union nested in `struct sigaction`.
    this.getDeclaringType().getDeclaringType*().getName() = "sigaction"
  }
}

/**
 * Holds if `handler` is the value of a `sa_handler`/`sa_sigaction` field of
 * `v` that reaches `call` without being overwritten.
 */
private predicate sigactionVariableHandler(Variable v, SigactionCall call, Function handler) {
  (
    exists(AssignExpr assign, FieldAccess field, FunctionAccess fa |
      assign.getRValue().getUnconverted() = fa and
      fa.getTarget() = handler and
      assign.getLValue() = field and
      sigactionHandlerFieldAccess(v, field) and
      reachesSigactionCallWithoutHandlerFieldWrite(v, assign, call)
    )
    or
    exists(ClassAggregateLiteral agg, FunctionAccess fa |
      agg.getAFieldExpr(any(SigactionHandlerField f)).getUnconverted() = fa and
      fa.getTarget() = handler and
      agg.getParent*() = v.getInitializer().getExpr() and
      reachesSigactionCallWithoutHandlerFieldWrite(v, v.getInitializer().getExpr(), call)
    )
  )
}

private predicate sigactionHandlerFieldAccess(Variable v, FieldAccess field) {
  field.getTarget() instanceof SigactionHandlerField and
  field.getQualifier*().(VariableAccess).getTarget() = v
}

private predicate sigactionHandlerFieldWrite(Variable v, ControlFlowNode node) {
  exists(AssignExpr assign, FieldAccess field |
    node = assign and
    assign.getLValue() = field and
    sigactionHandlerFieldAccess(v, field)
  )
}

/**
 * Holds if there is a path from `node` to `call` without an intervening
 * assignment to either handler field of `v`.
 */
private predicate reachesSigactionCallWithoutHandlerFieldWrite(
  Variable v, ControlFlowNode node, SigactionCall call
) {
  node = call
  or
  exists(ControlFlowNode successor |
    successor = node.getASuccessor() and
    not sigactionHandlerFieldWrite(v, successor) and
    reachesSigactionCallWithoutHandlerFieldWrite(v, successor, call)
  )
}

/**
 * A call that installs `handler` as a signal handler. This is either a call
 * to `signal` (or a variant) whose handler argument refers to `handler`, or a
 * call to `sigaction` whose `act` argument points to a `struct sigaction`
 * variable whose handler field is set to `handler`.
 */
class SignalHandlerInstallation extends FunctionCall {
  Function handler;

  SignalHandlerInstallation() {
    this.(SignalFunctionCall).getHandlerExpr().getUnconverted().(FunctionAccess).getTarget() =
      handler
    or
    exists(Variable v, SigactionCall call |
      this = call and
      call.getArgument(1).getUnconverted().(AddressOfExpr).getOperand() = v.getAnAccess() and
      sigactionVariableHandler(v, call, handler)
    )
  }

  /** Gets the installed handler function. */
  Function getHandler() { result = handler }

  /** Gets the expression for the signal number. */
  Expr getSignalExpr() { result = this.getArgument(0) }
}

/**
 * A function that is used as a signal handler, that is, a function that is
 * passed to `signal` (or a variant) or stored into the `sa_handler` or
 * `sa_sigaction` field of a `struct sigaction`.
 */
class SignalHandler extends Function {
  SignalHandler() {
    this = any(SignalHandlerInstallation i).getHandler()
    or
    sigactionVariableHandler(_, _, this)
    or
    exists(AssignExpr assign, FieldAccess field |
      assign.getRValue().getUnconverted().(FunctionAccess).getTarget() = this and
      assign.getLValue() = field and
      field.getTarget() instanceof SigactionHandlerField
    )
  }

  /**
   * Gets a function that may execute in the context of this signal handler:
   * the handler itself or a function it (transitively) calls.
   */
  Function getAReachableFunction() { this.calls*(result) }
}

/**
 * Holds if `call` may change the disposition of, or block, the signal that
 * `install` installs a handler for. Such a call ends the window in which
 * `install`'s handler can run asynchronously.
 */
predicate disablesSignal(SignalHandlerInstallation install, FunctionCall call) {
  // Re-registering a disposition for the same signal (e.g. `SIG_DFL`/`SIG_IGN`).
  (
    call instanceof SignalFunctionCall
    or
    call instanceof SigactionCall and
    not call.(SigactionCall).getArgument(1).getValue() = "0"
  ) and
  call != install and
  not call.(SignalHandlerInstallation).getHandler() = install.getHandler() and
  sameSignal(install.getSignalExpr(), call.getArgument(0))
  or
  // Blocking signals.
  call.getTarget()
      .hasGlobalOrStdName(["sigprocmask", "pthread_sigmask", "sighold", "sigblock", "sigsetmask"])
}

bindingset[a, b]
private predicate sameSignal(Expr a, Expr b) {
  a.getValue() = b.getValue()
  or
  not exists(a.getValue())
  or
  not exists(b.getValue())
}
