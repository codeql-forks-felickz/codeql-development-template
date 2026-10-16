/**
 * @name Assembly loaded from a relative file name
 * @description Loading an assembly from a constant relative file name resolves it through the
 *              current directory or assembly probing paths, which an attacker who controls those
 *              locations can use to plant a malicious assembly.
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

/** Holds if `name` looks like an assembly file name rather than an assembly identity. */
bindingset[name]
predicate isAssemblyFileName(string name) { name.regexpMatch("(?is).*\\.(dll|exe)") }

/** Gets a constant string value that reaches `e`, either directly or through local data flow. */
string getAConstantValue(Expr e) {
  result = e.getValue() and e.getType() instanceof StringType
  or
  exists(StringLiteral lit |
    DataFlow::localExprFlow(lit, e) and
    result = lit.getValue()
  )
}

from MethodCall mc, Method m, string name, string value
where
  m = mc.getTarget() and
  m.getDeclaringType().getABaseType*().hasFullyQualifiedName("System.Reflection", "Assembly") and
  name = m.getName() and
  m.getParameter(0).getType() instanceof StringType and
  value = getAConstantValue(mc.getArgument(0)) and
  not isAbsolutePath(value) and
  (
    // `Load` and `LoadWithPartialName` expect an assembly identity; a file name means the
    // assembly is located by probing the application search path.
    name = ["Load", "LoadWithPartialName"] and isAssemblyFileName(value)
    or
    // `LoadFrom` and `UnsafeLoadFrom` resolve relative paths against the current directory.
    name = ["LoadFrom", "UnsafeLoadFrom"]
  )
select mc,
  "Assembly '" + value + "' is loaded with " + name +
    " from a relative file name and is resolved through a search path that may be attacker-controlled."
