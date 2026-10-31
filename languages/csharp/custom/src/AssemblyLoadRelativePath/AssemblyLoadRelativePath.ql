/**
 * @name File-like assembly identity or relative assembly path
 * @description Passing a file-like name to an identity-based assembly loader may indicate a
 *              mistaken assumption about which assembly is loaded, while relative path-based
 *              loading resolves through the current directory.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.3
 * @precision medium
 * @id cs/assembly-load-relative-path
 * @tags security
 *       external/cwe/cwe-426
 *       external/cwe/cwe-114
 */

import csharp

/** Holds if `path` is an absolute Windows, UNC or POSIX path. */
bindingset[path]
predicate isAbsolutePath(string path) { path.regexpMatch("(?s)([A-Za-z]:[\\\\/]|[\\\\/]).*") }

/** Holds if `name` looks like a file name, despite being interpreted as an assembly identity. */
bindingset[name]
predicate isAssemblyFileName(string name) { name.regexpMatch("(?is).*\\.(dll|exe)") }

/** Gets an alert message that distinguishes identity-based and path-based loaders. */
bindingset[name, value]
private predicate getAlertMessage(string name, string value, string message) {
  name = "Load" and
  message =
    "Assembly '" + value + "' is passed to " + name +
      " as an assembly identity, not a file path. The runtime probes for an assembly such as '" +
      value + ".dll' through its search paths."
  or
  name = "LoadWithPartialName" and
  message =
    "Assembly '" + value + "' is passed to " + name +
      " as an assembly identity, not a file path. It may resolve to an assembly found through the assembly search paths."
  or
  name = ["LoadFrom", "UnsafeLoadFrom"] and
  message =
    "Assembly '" + value + "' is loaded with " + name +
      " from a relative path resolved against the current directory, which may be attacker-controlled."
}

/** Gets a constant string value that reaches `e`, either directly or through local data flow. */
string getAConstantValue(Expr e) {
  result = e.getValue() and e.getType() instanceof StringType
  or
  exists(StringLiteral lit |
    DataFlow::localExprFlow(lit, e) and
    result = lit.getValue()
  )
}

from MethodCall mc, Method m, string name, string value, string message
where
  m = mc.getTarget() and
  m.getDeclaringType().getABaseType*().hasFullyQualifiedName("System.Reflection", "Assembly") and
  name = m.getName() and
  m.getParameter(0).getType() instanceof StringType and
  value = getAConstantValue(mc.getArgument(0)) and
  not isAbsolutePath(value) and
  (
    // `Load` and `LoadWithPartialName` accept an assembly identity, not a file path.
    name = ["Load", "LoadWithPartialName"] and isAssemblyFileName(value)
    or
    // `LoadFrom` and `UnsafeLoadFrom` resolve relative paths against the current directory.
    name = ["LoadFrom", "UnsafeLoadFrom"]
  ) and
  getAlertMessage(name, value, message)
select mc, message
