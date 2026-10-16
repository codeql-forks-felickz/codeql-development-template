/**
 * @name Request handler with unexitable loop
 * @description A loop with a constant `true` condition and no reachable `break`,
 *              `return` or escaping exception, executed while handling a remote request,
 *              never lets the request complete and can be used to exhaust server threads.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id java/request-handler-infinite-loop
 * @tags security
 *       external/cwe/cwe-835
 */

import java
import semmle.code.java.frameworks.Servlets
import semmle.code.java.frameworks.JaxWS
import semmle.code.java.frameworks.spring.SpringController

/** A method that is invoked to handle a remote (HTTP) request. */
class RequestHandler extends Method {
  RequestHandler() {
    this.fromSource() and
    (
      isServletRequestMethod(this) or
      this instanceof SpringRequestMappingMethod or
      this instanceof JaxRsResourceMethod
    )
  }
}

/** Holds if `loop` has no condition, or a condition that is the compile-time constant `true`. */
predicate unconditionalLoop(LoopStmt loop) {
  loop instanceof ForStmt and not exists(loop.(ForStmt).getCondition())
  or
  loop.getCondition().(CompileTimeConstantExpr).getBooleanValue() = true
}

/** Holds if `s` is lexically inside the body of `loop`, in the same callable. */
predicate inLoopBody(LoopStmt loop, Stmt s) {
  s.getEnclosingStmt*() = loop.getBody() and
  s.getEnclosingCallable() = loop.getEnclosingCallable()
}

/**
 * Holds if an exception of type `ex` raised at `s` is caught by a `try` statement
 * that is itself inside the body of `loop`.
 */
predicate caughtInLoop(LoopStmt loop, Stmt s, RefType ex) {
  exists(TryStmt t |
    inLoopBody(loop, t) and
    s.getEnclosingStmt*() = t.getBlock() and
    ex.getAnAncestor() = t.getACatchClause().getACaughtType()
  )
}

/**
 * Holds if `exit` is a statement in `loop` that can transfer control out of the loop:
 * a `return`, a `break` or `continue` that targets the loop or an enclosing statement,
 * a `throw` that is not caught inside the loop, or a call to a method that declares a
 * checked exception that is not caught inside the loop.
 */
predicate loopExit(LoopStmt loop, Stmt exit) {
  inLoopBody(loop, exit) and
  (
    exit instanceof ReturnStmt
    or
    exit.(BreakStmt).getTarget() = loop.getEnclosingStmt*()
    or
    exit.(ContinueStmt).getTarget() = loop.getEnclosingStmt+()
    or
    exists(ThrowStmt throw | throw = exit |
      not caughtInLoop(loop, throw, throw.getExpr().getType())
    )
    or
    exists(Call c, RefType ex |
      c.getEnclosingStmt() = exit and
      ex = c.getCallee().getAThrownExceptionType() and
      not ex.getAnAncestor() instanceof TypeRuntimeException and
      not ex.getAnAncestor() instanceof TypeError and
      not caughtInLoop(loop, exit, ex)
    )
  )
}

from LoopStmt loop, RequestHandler handler
where
  unconditionalLoop(loop) and
  not loopExit(loop, _) and
  loop.getEnclosingCallable().fromSource() and
  handler.polyCalls*(loop.getEnclosingCallable())
select loop, "This loop has no reachable exit, so the request handled by $@ never completes.",
  handler, handler.getDeclaringType().getName() + "." + handler.getName()
