/**
 * Provides extensible predicates (populated via data extensions in `ext/*.model.yml`)
 * for modeling privilege-changing functions and named-pipe creation functions.
 */

import cpp

/**
 * Holds if the function `name` in namespace `namespace` (use `""` for the global
 * namespace) changes the privileges of the calling thread or process, and its
 * return value must be checked to determine whether the change succeeded.
 */
extensible predicate privilegeChangeFunctionModel(string namespace, string name);

/**
 * Holds if the function `name` in namespace `namespace` (use `""` for the global
 * namespace) creates a named pipe server instance, and the argument at index
 * `openModeArg` is the pipe open mode bit mask.
 */
extensible predicate namedPipeCreationFunctionModel(string namespace, string name, int openModeArg);

/** A function whose return value reports whether a privilege change succeeded. */
class PrivilegeChangeFunction extends Function {
  PrivilegeChangeFunction() {
    exists(string namespace, string name |
      privilegeChangeFunctionModel(namespace, name) and
      this.hasQualifiedName(namespace, name)
    )
  }
}

/** A function that creates a named pipe server instance. */
class NamedPipeCreationFunction extends Function {
  int openModeArg;

  NamedPipeCreationFunction() {
    exists(string namespace, string name |
      namedPipeCreationFunctionModel(namespace, name, openModeArg) and
      this.hasQualifiedName(namespace, name)
    )
  }

  /** Gets the index of the open mode argument. */
  int getOpenModeArgIndex() { result = openModeArg }
}
