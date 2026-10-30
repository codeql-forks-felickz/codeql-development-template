/**
 * @name Time-of-check time-of-use filesystem race condition on a constant path
 * @description Separately checking the state of a file named by a constant
 *              path (for example a predictable `/tmp` file) before operating
 *              on it may allow an attacker to modify the file between the two
 *              operations.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.7
 * @precision high
 * @id cpp/toctou-race-condition-constant-path
 * @tags security
 *       external/cwe/cwe-367
 */

import cpp
import TOCTOUFilesystemRace

from Expr check, Expr checkPath, FunctionCall use, Expr usePath
where
  checkUse(check, checkPath, use, usePath) and
  sameConstantPath(checkPath, usePath)
select use,
  "The $@ being operated upon was previously $@, but the underlying file may have been changed since then.",
  usePath, "filename", check, "checked"
