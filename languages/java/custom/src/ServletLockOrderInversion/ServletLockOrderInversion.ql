/**
 * @name Lock order inversion in request handler
 * @description A servlet or controller that acquires the same two shared locks in opposite
 *              orders while handling requests can deadlock when requests are processed
 *              concurrently, permanently blocking request threads.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.9
 * @precision medium
 * @id java/servlet-lock-order-inversion
 * @tags security
 *       external/cwe/cwe-833
 *       external/cwe/cwe-667
 */

import java
import semmle.code.java.frameworks.Servlets
import semmle.code.java.frameworks.spring.SpringController

/** A method that handles requests on a shared (singleton) servlet or controller instance. */
class RequestHandlerMethod extends Method {
  RequestHandlerMethod() {
    this.getDeclaringType().getASourceSupertype*() instanceof ServletClass and
    this.hasName([
        "service", "doGet", "doPost", "doPut", "doDelete", "doHead", "doOptions", "doTrace"
      ])
    or
    this instanceof SpringRequestMappingMethod
  }
}

/**
 * Gets the field used as the monitor of `s`, if it is a static field or a field of the
 * current instance, i.e. a lock that is shared between all requests handled by that instance.
 */
Field sharedLockField(SynchronizedStmt s) {
  exists(FieldAccess fa | fa = s.getExpr() and result = fa.getField() |
    result.isStatic() or fa.isOwnFieldAccess()
  )
}

/** Holds if `inner` may be executed while the monitor of `outer` is held. */
predicate acquiredWhileHolding(SynchronizedStmt outer, SynchronizedStmt inner) {
  inner.getEnclosingCallable() = outer.getEnclosingCallable() and
  inner.getParent+() = outer
  or
  exists(Call c |
    c.getEnclosingCallable() = outer.getEnclosingCallable() and
    c.getEnclosingStmt().getParent+() = outer and
    c.getCallee().getSourceDeclaration().polyCalls*(inner.getEnclosingCallable())
  )
}

/**
 * Holds if `outer` holds the monitor of `first` while `inner` acquires the monitor of `second`,
 * and `outer` can be reached from a request handler of a class that declares or inherits both
 * fields.
 */
predicate lockOrder(SynchronizedStmt outer, Field first, SynchronizedStmt inner, Field second) {
  acquiredWhileHolding(outer, inner) and
  first = sharedLockField(outer) and
  second = sharedLockField(inner) and
  first != second and
  exists(RequestHandlerMethod handler |
    handler.polyCalls*(outer.getEnclosingCallable()) and
    handler.getDeclaringType().getASourceSupertype*() = first.getDeclaringType() and
    handler.getDeclaringType().getASourceSupertype*() = second.getDeclaringType()
  )
}

from
  SynchronizedStmt outer, Field first, SynchronizedStmt inner, Field second,
  SynchronizedStmt otherOuter
where
  lockOrder(outer, first, inner, second) and
  lockOrder(otherOuter, second, _, first)
select outer.getExpr(),
  "This acquires lock '" + first.getName() +
    "' and then $@ while handling a request, but $@ acquires them in the opposite order, so concurrent requests can deadlock.",
  inner.getExpr(), "'" + second.getName() + "'", otherOuter.getExpr(), "this statement"
