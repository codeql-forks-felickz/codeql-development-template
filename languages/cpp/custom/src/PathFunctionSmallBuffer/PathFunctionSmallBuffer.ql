/**
 * @name Path manipulation function called with a buffer smaller than the maximum path size
 * @description Path manipulation functions such as `PathAppend` and `realpath`
 *              assume that their output buffer can hold a maximum-length path.
 *              Passing a smaller buffer can cause a buffer overflow.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id cpp/custom/path-function-small-buffer
 * @tags security
 *       external/cwe/cwe-785
 *       external/cwe/cwe-120
 *       external/cwe/cwe-121
 */

import cpp

/**
 * Holds if `name` is a path manipulation function that writes up to `required`
 * elements to the buffer passed as argument `arg` without taking its size.
 */
predicate pathFunction(string name, int arg, int required) {
  required = 260 and
  arg = 0 and
  exists(string base |
    base =
      [
        "PathAppend", "PathCombine", "PathCanonicalize", "PathAddBackslash", "PathAddExtension",
        "PathRenameExtension", "PathRelativePathTo"
      ]
  |
    name = [base, base + "A", base + "W"]
  )
  or
  // `PathCompactPath` takes a device context first.
  name = ["PathCompactPath", "PathCompactPathA", "PathCompactPathW"] and
  arg = 1 and
  required = 260
  or
  // POSIX `realpath` writes up to `PATH_MAX` bytes to its second argument.
  name = "realpath" and arg = 1 and required = 4096
}

from FunctionCall call, string name, int arg, int required, Expr buffer, ArrayType t
where
  call.getTarget().hasGlobalName(name) and
  pathFunction(name, arg, required) and
  buffer = call.getArgument(arg).getUnconverted() and
  t = buffer.getUnspecifiedType() and
  t.getArraySize() < required
select buffer,
  "This buffer has " + t.getArraySize() + " elements, but " + name + " may write up to " + required +
    " elements to it."
