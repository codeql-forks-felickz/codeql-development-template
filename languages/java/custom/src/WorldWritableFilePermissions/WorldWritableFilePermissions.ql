/**
 * @name World-writable file permissions
 * @description Granting write permission to all users on a file (for example with
 *              `chmod 777`) lets any local user replace or modify it, which can lead
 *              to code execution when the file is later executed or loaded.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision high
 * @id java/world-writable-file-permissions
 * @tags security
 *       external/cwe/cwe-732
 */

import java
import semmle.code.java.security.FileWritable

/** Holds if `mode` is a `chmod` mode argument that grants write permission to others. */
bindingset[mode]
predicate isWorldWritableMode(string mode) {
  // Octal mode whose last digit includes the write bit (2, 3, 6 or 7).
  mode.regexpMatch("0*[0-7]?[0-7]?[0-7]?[2367]") and mode.regexpMatch("[0-7]{1,5}")
  or
  // Symbolic mode such as `o+w`, `a+rwx`, `ugo=rw` or `u+x,o+w`.
  mode.regexpMatch("(.*,)?[ugo]*[oa][ugo]*[+=][rwxXst]*w.*")
}

/** Gets the constant prefix of the string expression `e`. */
string constantPrefix(Expr e) {
  result = e.(CompileTimeConstantExpr).getStringValue()
  or
  not e instanceof CompileTimeConstantExpr and
  result = constantPrefix(e.(AddExpr).getLeftOperand())
}

/** Holds if `cmd` is a constant `chmod` command line that makes a file world-writable. */
bindingset[cmd]
predicate isWorldWritableChmodCommand(string cmd) {
  exists(string mode |
    mode = cmd.regexpCapture("\\s*(?:\\S*/)?chmod\\s+(?:-[A-Za-z]+\\s+)*(\\S+)(?:\\s.*)?", 1) and
    isWorldWritableMode(mode)
  )
}

/** A call that runs an operating system command (`Runtime.exec` or `new ProcessBuilder`). */
class CommandCall extends Call {
  CommandCall() {
    this.(MethodCall).getMethod().hasName("exec") and
    this.(MethodCall).getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime")
    or
    this.(ClassInstanceExpr).getConstructedType().hasQualifiedName("java.lang", "ProcessBuilder")
  }

  /** Gets the `i`th command-line token passed as a separate argument, if known. */
  Expr getToken(int i) {
    exists(ArrayInit init |
      init = this.getArgument(0).(ArrayCreationExpr).getInit() and result = init.getInit(i)
    )
    or
    this instanceof ClassInstanceExpr and
    this.getNumArgument() > 1 and
    result = this.getArgument(i)
    or
    exists(MethodCall asList |
      asList = this.getArgument(0) and
      asList.getMethod().hasName(["asList", "of"]) and
      asList.getMethod().getDeclaringType().hasQualifiedName("java.util", ["Arrays", "List"]) and
      result = asList.getArgument(i)
    )
  }
}

/** Holds if `e` makes a file world-writable, described by `what`. */
predicate setsWorldWritable(Expr e, string what) {
  // `Runtime.exec("chmod 777 " + path)`.
  exists(CommandCall call |
    e = call and
    call.getArgument(0).getType() instanceof TypeString and
    isWorldWritableChmodCommand(constantPrefix(call.getArgument(0))) and
    what = "a 'chmod' command"
  )
  or
  // `new ProcessBuilder("chmod", "777", path)` and similar token arrays.
  exists(CommandCall call, int i, string mode |
    e = call and
    call.getToken(0).(CompileTimeConstantExpr).getStringValue().regexpMatch("(\\S*/)?chmod") and
    i > 0 and
    mode = call.getToken(i).(CompileTimeConstantExpr).getStringValue() and
    not exists(int j | j in [1 .. i - 1] |
      not call.getToken(j).(CompileTimeConstantExpr).getStringValue().matches("-%")
    ) and
    not mode.matches("-%") and
    isWorldWritableMode(mode) and
    what = "a 'chmod' command"
  )
  or
  // `file.setWritable(true, false)` and `Files.setPosixFilePermissions(path, perms)` with `OTHERS_WRITE`.
  e instanceof SetFileWorldWritable and
  e.(MethodCall).getMethod().hasName(["setWritable", "setPosixFilePermissions"]) and
  what = "a call to '" + e.(MethodCall).getMethod().getName() + "'"
  or
  // `PosixFilePermissions.fromString("rwxrwxrwx")`.
  exists(MethodCall fromString |
    e = fromString and
    fromString.getMethod().hasName("fromString") and
    fromString
        .getMethod()
        .getDeclaringType()
        .hasQualifiedName("java.nio.file.attribute", "PosixFilePermissions") and
    fromString.getArgument(0).(CompileTimeConstantExpr).getStringValue().charAt(7) = "w" and
    what = "a POSIX permission string"
  )
}

from Expr e, string what
where setsWorldWritable(e, what)
select e, "This makes a file world-writable using " + what + "."
