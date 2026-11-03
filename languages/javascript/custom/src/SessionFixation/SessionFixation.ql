/**
 * @name Failure to abandon session
 * @description Reusing an existing session as a different user could allow
 *              an attacker to access someone else's account by using
 *              their session.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5
 * @precision medium
 * @id js/session-fixation
 * @tags security
 *       external/cwe/cwe-384
 */

// This query is a superset of the standard `js/session-fixation` query
// (codeql/javascript-queries, Security/CWE-384/SessionFixation.ql). In addition it
// tracks the `req.session` object across function calls, so that a login handler which
// passes the session to a helper that marks it as authenticated (or regenerates it) is
// handled like a handler that writes to (or regenerates) `req.session` directly.
import javascript

/**
 * Gets a reference to the session object (`req.session`) of a request handled by `handler`,
 * including references obtained by passing the session object to another function.
 */
private DataFlow::SourceNode sessionRef(Express::RouteHandler handler, DataFlow::TypeTracker t) {
  t.start() and
  result = handler.getARequestSource().ref().getAPropertyRead("session")
  or
  exists(DataFlow::TypeTracker t2 | result = sessionRef(handler, t2).track(t2, t))
}

/** Gets a reference to the session object of a request handled by `handler`. */
private DataFlow::SourceNode sessionRef(Express::RouteHandler handler) {
  result = sessionRef(handler, DataFlow::TypeTracker::end())
}

/**
 * Holds if `setup` uses express-session (or similar) to log in a user.
 */
pragma[inline]
predicate isLoginSetup(Express::RouteSetup setup) {
  // some path that contains "login" with a write to `req.session`
  setup.getPath().matches("%login%") and
  exists(sessionRef(setup.getARouteHandler()).getAPropertyWrite())
  // passport used to be recognized, but they have since added built-in protection against session fixation
}

/**
 * Holds if `setup` regenerates its session using `req.session.regenerate`.
 */
pragma[inline]
predicate regeneratesSession(Express::RouteSetup setup) {
  exists(sessionRef(setup.getARouteHandler()).getAPropertyRead("regenerate"))
}

from Express::RouteSetup setup
where
  isLoginSetup(setup) and
  not regeneratesSession(setup)
select setup, "Route handler does not invalidate session following login."
