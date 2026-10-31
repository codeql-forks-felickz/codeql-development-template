/**
 * @name Named pipe created without FILE_FLAG_FIRST_PIPE_INSTANCE
 * @description Creating a named pipe server without FILE_FLAG_FIRST_PIPE_INSTANCE lets a
 *              local attacker that has already created an instance of the same pipe name
 *              intercept or impersonate clients (named-pipe squatting).
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.5
 * @precision medium
 * @id cpp/named-pipe-missing-first-instance
 * @tags security
 *       external/cwe/cwe-284
 */

import cpp
import lib.PrivilegeModels

/** The value of the Win32 `FILE_FLAG_FIRST_PIPE_INSTANCE` open mode flag. */
float fileFlagFirstPipeInstance() { result = 524288.0 } // 0x00080000

/**
 * Holds if the compile-time constant `openMode` has the
 * `FILE_FLAG_FIRST_PIPE_INSTANCE` bit set.
 */
bindingset[openMode]
predicate hasFirstPipeInstanceFlag(float openMode) {
  (openMode / fileFlagFirstPipeInstance()).floor() % 2 = 1
}

from FunctionCall call, NamedPipeCreationFunction f, Expr openMode
where
  call.getTarget() = f and
  openMode = call.getArgument(f.getOpenModeArgIndex()) and
  // Only report compile-time constant open modes (dwOpenMode is an unsigned 32-bit mask,
  // so the value is read as a float to avoid overflowing QL's signed 32-bit int).
  exists(float value |
    value = openMode.getValue().toFloat() and
    not hasFirstPipeInstanceFlag(value)
  )
select call,
  "Named pipe is created by $@ without FILE_FLAG_FIRST_PIPE_INSTANCE in its open mode, so it may be squatted by a pre-existing instance.",
  f, f.getName()
