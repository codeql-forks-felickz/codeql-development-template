/**
 * @name Insecure temporary file opened without exclusive creation
 * @description Opening a file whose name was produced by a predictable temporary-name
 *              generator such as `tmpnam` or `mktemp` without exclusive creation
 *              (for example `O_CREAT` without `O_EXCL`) allows a local attacker to
 *              pre-create or symlink the path between name generation and use.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision high
 * @id cpp/insecure-temporary-file-open
 * @tags security
 *       external/cwe/cwe-377
 *       external/cwe/cwe-367
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

/** A function that returns a predictable, not-yet-created temporary file name. */
class TemporaryNameFunction extends Function {
  TemporaryNameFunction() {
    this.hasGlobalOrStdName([
        "tmpnam", "tmpnam_r", "tempnam", "mktemp", "_tempnam", "_wtempnam", "_wtmpnam", "_mktemp",
        "_wmktemp"
      ])
  }

  /** Holds if this function writes the generated name into the buffer at argument `i`. */
  predicate writesNameToArgument(int i) {
    this.hasGlobalOrStdName(["tmpnam", "tmpnam_r", "mktemp", "_wtmpnam", "_mktemp", "_wmktemp"]) and
    i = 0
  }
}

/** Holds if `e` contains an expansion of a macro named one of `names`. */
bindingset[names]
private predicate hasFlagMacro(Expr e, string names) {
  exists(MacroInvocation mi |
    mi.getMacroName() = names.splitAt(",") and
    mi.getAnExpandedElement() = e.getAChild*()
  )
}

/** Holds if `e` uses any `O_*` flag macro (so macro names are authoritative). */
private predicate usesFlagMacros(Expr e) {
  exists(MacroInvocation mi |
    mi.getMacroName().regexpMatch("_?O_[A-Z_]+") and
    mi.getAnExpandedElement() = e.getAChild*()
  )
}

/** Holds if the open-style `flags` expression requests creation (`O_CREAT`). */
private predicate hasCreateFlag(Expr flags) {
  hasFlagMacro(flags, "O_CREAT,_O_CREAT")
  or
  not usesFlagMacros(flags) and flags.getValue().toInt().bitAnd(64) != 0
}

/** Holds if the open-style `flags` expression requests exclusive creation (`O_EXCL`). */
private predicate hasExclusiveFlag(Expr flags) {
  hasFlagMacro(flags, "O_EXCL,_O_EXCL")
  or
  not usesFlagMacros(flags) and flags.getValue().toInt().bitAnd(128) != 0
}

/**
 * Holds if `call` creates or opens the file at `path` in a way that does not fail
 * when the path already exists (non-exclusive creation).
 */
predicate nonExclusiveCreate(FunctionCall call, Expr path) {
  exists(Function f, int pathIdx, int flagsIdx, Expr flags |
    f = call.getTarget() and
    (
      f.hasGlobalName(["open", "open64", "_open", "_wopen"]) and pathIdx = 0 and flagsIdx = 1
      or
      f.hasGlobalName(["openat", "openat64"]) and pathIdx = 1 and flagsIdx = 2
    ) and
    path = call.getArgument(pathIdx) and
    flags = call.getArgument(flagsIdx) and
    hasCreateFlag(flags) and
    not hasExclusiveFlag(flags)
  )
  or
  call.getTarget().hasGlobalName(["creat", "creat64", "_creat", "_wcreat"]) and
  path = call.getArgument(0)
  or
  exists(string mode |
    call.getTarget().hasGlobalOrStdName(["fopen", "fopen64", "_wfopen"]) and
    path = call.getArgument(0) and
    mode = call.getArgument(1).getValue() and
    mode.regexpMatch("[wa].*") and
    not mode.matches("%x%")
  )
}

module InsecureTemporaryFileConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(FunctionCall call, TemporaryNameFunction f | call.getTarget() = f |
      source.asIndirectExpr() = call
      or
      exists(int i |
        f.writesNameToArgument(i) and
        source.asDefiningArgument() = call.getArgument(i)
      )
    )
  }

  predicate isSink(DataFlow::Node sink) { nonExclusiveCreate(_, sink.asIndirectExpr()) }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module InsecureTemporaryFileFlow = TaintTracking::Global<InsecureTemporaryFileConfig>;

import InsecureTemporaryFileFlow::PathGraph

from
  InsecureTemporaryFileFlow::PathNode source, InsecureTemporaryFileFlow::PathNode sink,
  FunctionCall openCall
where
  InsecureTemporaryFileFlow::flowPath(source, sink) and
  nonExclusiveCreate(openCall, sink.getNode().asIndirectExpr())
select openCall, source, sink,
  "This call creates a file at a path from $@, which generates a predictable temporary file name, without exclusive creation.",
  source, "this temporary-name generator"
