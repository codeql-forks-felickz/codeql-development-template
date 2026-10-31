/**
 * @name Database connection pool opened repeatedly without being closed
 * @description Opening a new `*sql.DB` in code that runs repeatedly (for example, per request)
 *              and never closing it leaks a connection pool, its background goroutine and
 *              any underlying file descriptors or sockets, which can exhaust server resources.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id go/resource-exhaustion-dos
 * @tags security
 *       external/cwe/cwe-772
 *       external/cwe/cwe-400
 */

import go

/** A call to `database/sql.Open` or `database/sql.OpenDB`, which creates a new connection pool. */
class SqlDbOpenCall extends DataFlow::CallNode {
  SqlDbOpenCall() { this.getTarget().hasQualifiedName("database/sql", ["Open", "OpenDB"]) }

  /** Gets the data-flow node for the `*sql.DB` result of this call. */
  DataFlow::Node getDbResult() {
    if this.getTarget().getName() = "Open"
    then result = this.getResult(0)
    else result = this.getResult()
  }
}

/** Holds if `f` is a `main` or `init` function, which runs once per process. */
predicate isStartupFunction(FuncDef f) {
  f instanceof FuncDecl and
  not f instanceof MethodDecl and
  f.getName() = ["main", "init"]
}

/** Holds if `n` is inside the body of a loop in its own enclosing function. */
predicate isInLoop(AstNode n) {
  exists(LoopStmt loop |
    loop.getEnclosingFunction() = n.getEnclosingFunction() and
    loop.getBody() = n.getParent+()
  )
}

/**
 * Holds if `f` may be executed many times during the life of the process.
 *
 * This is approximated as any function other than `main` and `init` that is either
 * never called directly (for example, an HTTP handler registered as a callback), or
 * is called from within a loop or from another repeatedly executed function.
 */
predicate isRepeatable(FuncDef f) {
  not isStartupFunction(f) and
  (
    not exists(DataFlow::CallNode c | c.getACallee() = f)
    or
    exists(DataFlow::CallNode c | c.getACallee() = f |
      isInLoop(c.asExpr()) or
      isRepeatable(c.asExpr().getEnclosingFunction())
    )
  )
}

/**
 * Holds if the reference `ref` to `v` is a read that is the receiver of a method
 * named `name` (for example, `v.Query(...)` or `v.Close`).
 */
predicate isMethodReceiverUse(LocalVariable v, Ident ref, string name) {
  ref = v.getAReference() and
  exists(SelectorExpr sel | sel.getBase() = ref and sel.getSelector().getName() = name)
}

/** Holds if `v` is closed by a call (or method value) of `Close`. */
predicate isClosed(LocalVariable v) { isMethodReceiverUse(v, _, "Close") }

/**
 * Holds if the value of `v` may escape the current function, for example by being
 * returned, stored in a field, global, or composite literal, passed to another
 * function, sent on a channel, or having its address taken.
 */
predicate mayEscape(LocalVariable v) {
  exists(Ident ref |
    ref = v.getAReference() and
    not ref.(ReferenceExpr).isLvalue() and
    not isMethodReceiverUse(v, ref, _)
  )
}

from SqlDbOpenCall open, LocalVariable v, Write w
where
  w.writes(v, open.getDbResult()) and
  not isClosed(v) and
  not mayEscape(v) and
  not open.getFile().getBaseName().matches("%\\_test.go") and
  (
    isInLoop(open.asExpr())
    or
    isRepeatable(open.asExpr().getEnclosingFunction())
  )
select open,
  "This call opens a new database connection pool that is never closed. Repeated execution can exhaust connections, goroutines and file descriptors."
