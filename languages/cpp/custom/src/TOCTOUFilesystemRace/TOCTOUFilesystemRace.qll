/**
 * Provides predicates for finding time-of-check time-of-use (TOCTOU) filesystem
 * race conditions where the checked and used filename is a constant, such as a
 * string literal, a macro expanding to a string literal, or a global variable.
 *
 * The check/use logic mirrors the standard `cpp/toctou-race-condition` query
 * (`Security/CWE/CWE-367/TOCTOUFilesystemRace.ql` in `codeql/cpp-queries`),
 * which only relates paths held in the same SSA stack variable.
 */

import cpp
import semmle.code.cpp.controlflow.Guards

/**
 * An operation on a filename that is likely to modify the corresponding file
 * and may return an indication of success.
 */
FunctionCall filenameOperation(Expr path) {
  exists(string name | name = result.getTarget().getName() |
    name =
      [
        "remove", "unlink", "rmdir", "rename", "fopen", "open", "freopen", "_open", "_wopen",
        "_wfopen", "_fsopen", "_wfsopen"
      ] and
    result.getArgument(0) = path
    or
    name = ["fopen_s", "wfopen_s", "rename"] and
    result.getArgument(1) = path
  )
  or
  result = sensitiveFilenameOperation(path)
}

/**
 * An operation on a filename that is likely to modify the security properties
 * of the corresponding file and may return an indication of success.
 */
FunctionCall sensitiveFilenameOperation(Expr path) {
  exists(string name | name = result.getTarget().getName() |
    name = ["chmod", "chown"] and
    result.getArgument(0) = path
  )
}

/**
 * An operation on a filename that returns information in the return value but
 * does not modify the corresponding file.  For example, `access`.
 */
FunctionCall accessCheck(Expr path) {
  exists(string name | name = result.getTarget().getName() |
    name = ["access", "_access", "_waccess", "_access_s", "_waccess_s"]
  ) and
  path = result.getArgument(0)
}

/**
 * An operation on a filename that returns information via a pointer argument
 * and any return value, but does not modify the corresponding file.  For
 * example, `stat`.
 */
FunctionCall stat(Expr path, Expr buf) {
  exists(string name | name = result.getTarget().getName() |
    name = ["stat", "lstat", "fstat"] or
    name.matches("\\_stat%") or
    name.matches("\\_wstat%")
  ) and
  path = result.getArgument(0) and
  buf = result.getArgument(1)
}

/**
 * Holds if `use` refers to `source`, either by being the same or by
 * one step of variable indirection.
 */
predicate referenceTo(Expr source, Expr use) {
  source = use
  or
  exists(SsaDefinition def, StackVariable v |
    def.getAnUltimateDefiningValue(v) = source and def.getAUse(v) = use
  )
}

pragma[noinline]
private predicate statCallWithPointer(Expr checkPath, Expr call, Expr e, Variable v) {
  call = stat(checkPath, e) and
  e.getAChild*().(VariableAccess).getTarget() = v
}

/** Holds if `check` looks like a check on the filename `checkPath`. */
predicate checksPath(Expr check, Expr checkPath) {
  check = accessCheck(checkPath)
  or
  check = stat(checkPath, _)
  or
  exists(Expr e, Variable v |
    statCallWithPointer(checkPath, _, e, v) and
    check.(VariableAccess).getTarget() = v and
    not e.getAChild*() = check
  )
}

pragma[nomagic]
private predicate checkPathControlsUse(Expr check, Expr checkPath, Expr use) {
  exists(GuardCondition guard | referenceTo(check, guard.(Expr).getAChild*()) |
    guard.controls(use.getBasicBlock(), _)
  ) and
  checksPath(pragma[only_bind_into](check), checkPath)
}

pragma[nomagic]
private predicate fileNameOperationControlsUse(Expr check, Expr checkPath, Expr use) {
  exists(GuardCondition guard | referenceTo(check, guard.(Expr).getAChild*()) |
    guard.controls(use.getBasicBlock(), _)
  ) and
  pragma[only_bind_into](check) = filenameOperation(checkPath)
}

/**
 * Holds if `check` (a check on `checkPath`) is part of a guard that controls
 * `use` (an operation on `usePath`).
 */
predicate checkUse(Expr check, Expr checkPath, FunctionCall use, Expr usePath) {
  checkPathControlsUse(check, checkPath, use) and
  checksPath(check, checkPath) and
  use = filenameOperation(usePath)
  or
  fileNameOperationControlsUse(check, checkPath, use) and
  check = filenameOperation(checkPath) and
  use = sensitiveFilenameOperation(usePath)
}

/**
 * Holds if `checkPath` and `usePath` name the same file through a constant:
 * the same string literal value (including via a macro), or an access to the
 * same global or namespace-scope variable.
 *
 * Paths held in the same stack variable are already reported by the standard
 * `cpp/toctou-race-condition` query and are deliberately excluded here.
 */
bindingset[checkPath, usePath]
predicate sameConstantPath(Expr checkPath, Expr usePath) {
  checkPath instanceof StringLiteral and
  usePath instanceof StringLiteral and
  checkPath.getValue() = usePath.getValue()
  or
  exists(GlobalOrNamespaceVariable v |
    checkPath.(VariableAccess).getTarget() = v and
    usePath.(VariableAccess).getTarget() = v
  )
}
