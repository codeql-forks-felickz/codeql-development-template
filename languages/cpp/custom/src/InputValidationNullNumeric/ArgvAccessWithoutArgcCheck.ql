/**
 * @name Command-line argument accessed without checking argument count
 * @description Reading `argv[n]` in `main` without first checking that `argc`
 *              is greater than `n` reads a NULL pointer (or past the end of
 *              the argument vector) when the program is started with too few
 *              arguments.
 * @kind problem
 * @problem.severity warning
 * @security-severity 3.3
 * @precision medium
 * @id cpp/argv-access-without-argc-check
 * @tags security
 *       reliability
 *       external/cwe/cwe-476
 *       external/cwe/cwe-20
 */

import cpp
import semmle.code.cpp.controlflow.Dominance

/** A `main` (or `wmain`) function with `argc` and `argv` parameters. */
class MainFunction extends Function {
  MainFunction() {
    this.hasGlobalName(["main", "wmain"]) and
    this.getNumberOfParameters() >= 2
  }

  Parameter getArgc() { result = this.getParameter(0) }

  Parameter getArgv() { result = this.getParameter(1) }
}

/**
 * An access to `argv[index]` in `main` with a constant `index` of at least 1,
 * written either as `argv[index]` or as `*(argv + index)`.
 */
class ConstantArgvAccess extends Expr {
  MainFunction main;
  int index;

  ConstantArgvAccess() {
    exists(Expr base, Expr offset |
      (
        base = this.(ArrayExpr).getArrayBase() and
        offset = this.(ArrayExpr).getArrayOffset()
        or
        exists(PointerAddExpr add |
          add = this.(PointerDereferenceExpr).getOperand() and
          base = add.getLeftOperand() and
          offset = add.getRightOperand()
        )
      ) and
      base.(VariableAccess).getTarget() = main.getArgv() and
      index = offset.getValue().toInt() and
      index >= 1
    ) and
    // `&argv[n]` does not read the element.
    not this.getParent() instanceof AddressOfExpr and
    not this.isUnevaluated()
  }

  MainFunction getMain() { result = main }

  int getIndex() { result = index }
}

/** Holds if `e` is an expression that reads `argc` of `main`. */
predicate isArgcRead(Expr e, MainFunction main) { e.(VariableAccess).getTarget() = main.getArgc() }

/**
 * Holds if function `f` (transitively) calls a function that terminates the
 * process, such as `exit` or `abort`.
 */
predicate mayTerminate(Function f) {
  f.hasGlobalOrStdName([
      "exit", "_exit", "_Exit", "abort", "quick_exit", "err", "errx", "verr", "verrx"
    ])
  or
  exists(FunctionCall call |
    call.getEnclosingFunction() = f and
    mayTerminate(call.getTarget())
  )
}

/** Holds if statement `s` contains a statement or call that leaves the current path. */
predicate leavesPath(Stmt s) {
  exists(Stmt inner | inner.getParentStmt*() = s |
    inner instanceof ReturnStmt or
    inner instanceof GotoStmt or
    inner instanceof BreakStmt or
    inner instanceof ContinueStmt
  )
  or
  exists(FunctionCall call | call.getEnclosingStmt().getParentStmt*() = s |
    mayTerminate(call.getTarget())
  )
  or
  exists(ThrowExpr t | t.getEnclosingStmt().getParentStmt*() = s)
}

/**
 * Holds if `access` is only evaluated on one branch of a condition `cond`,
 * for example inside an `if`, loop, `?:` or the right operand of `&&`/`||`.
 *
 * This is purely syntactic so that it also works when several programs in
 * the same database define `main` (whose definitions are then merged).
 */
predicate isConditionallyEvaluated(ConstantArgvAccess access, Expr cond) {
  exists(IfStmt s | cond = s.getCondition() | access.getEnclosingStmt().getParentStmt+() = s)
  or
  exists(Loop l | cond = l.getCondition() |
    access.getEnclosingStmt().getParentStmt+() = l.getStmt()
  )
  or
  exists(ConditionalExpr c | cond = c.getCondition() |
    access.getParent*() = [c.getThen(), c.getElse()]
  )
  or
  exists(BinaryLogicalOperation op | cond = op.getLeftOperand() |
    access.getParent*() = op.getRightOperand()
  )
}

/**
 * Holds if `access` is protected by a check of `argc`: either the access is
 * only reached on one branch of a condition that reads `argc`, or a preceding
 * `if` statement that reads `argc` leaves the current path (by returning,
 * exiting or similar) when the check fails.
 */
predicate isArgcChecked(ConstantArgvAccess access) {
  exists(Expr cond, Expr argc |
    isConditionallyEvaluated(access, cond) and
    isArgcRead(argc, access.getMain()) and
    argc.getParent*() = cond and
    (
      not exists(Loop l | cond = l.getCondition())
      or
      dominates(argc, access)
    )
  )
  or
  exists(IfStmt ifStmt, Expr argc |
    isArgcRead(argc, access.getMain()) and
    argc.getParent*() = ifStmt.getCondition() and
    (leavesPath(ifStmt.getThen()) or leavesPath(ifStmt.getElse())) and
    dominates(argc, access)
  )
  or
  // `argc` is validated by a helper, for example `check_args(argc, argv)`, or
  // passed to an option parser such as `getopt`.
  exists(FunctionCall call, Expr argc |
    isArgcRead(argc, access.getMain()) and
    argc = call.getAnArgument() and
    dominates(call, access)
  )
}

from ConstantArgvAccess access
where not isArgcChecked(access)
select access,
  "argv[" + access.getIndex() + "] is read without checking that argc is greater than " +
    access.getIndex() + "; it is NULL when the program is run with fewer arguments."
