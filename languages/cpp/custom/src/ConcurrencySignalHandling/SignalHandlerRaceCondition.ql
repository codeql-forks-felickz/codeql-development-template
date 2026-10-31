/**
 * @name Shared data freed while signal handler is installed
 * @description Freeing a global variable that is also accessed by an installed
 *              signal handler, without first blocking the signal or removing the
 *              handler, lets a signal delivered in the middle of the update make the
 *              handler use freed memory.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.3
 * @precision medium
 * @id cpp/custom/signal-handler-race-condition
 * @tags security
 *       concurrency
 *       external/cwe/cwe-364
 *       external/cwe/cwe-416
 */

import cpp
import SignalHandlers

/**
 * Holds if `dealloc` frees the global variable `g` and `g` is accessed by a
 * function that may run as part of the signal handler installed by `install`,
 * which is in the same function as `dealloc`.
 */
predicate candidate(
  SignalHandlerInstallation install, DeallocationExpr dealloc, GlobalOrNamespaceVariable g
) {
  dealloc.getFreedExpr().getUnconverted() = g.getAnAccess() and
  dealloc.getEnclosingFunction() = install.getEnclosingFunction() and
  g.getAnAccess().getEnclosingFunction() =
    install.getHandler().(SignalHandler).getAReachableFunction()
}

/**
 * Gets a control-flow node that is reachable from `install` without passing
 * through a call that blocks the signal or replaces the installed handler.
 */
ControlFlowNode reachableWhileInstalled(SignalHandlerInstallation install) {
  candidate(install, _, _) and
  result = install.getASuccessor() and
  not disablesSignal(install, result)
  or
  result = reachableWhileInstalled(install).getASuccessor() and
  not disablesSignal(install, result)
}

from SignalHandlerInstallation install, DeallocationExpr dealloc, GlobalOrNamespaceVariable g
where
  candidate(install, dealloc, g) and
  dealloc = reachableWhileInstalled(install)
select dealloc,
  "Global variable $@ is freed while signal handler $@, which accesses it, is installed $@; a signal delivered here can make the handler use freed memory.",
  g, g.getName(), install.getHandler(), install.getHandler().getName(), install, "here"
