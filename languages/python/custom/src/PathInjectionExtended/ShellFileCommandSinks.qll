/**
 * Provides path-injection sinks for file paths passed to operating system
 * commands that access the file system, such as `mv`, `cp` or `cat`.
 *
 * The standard `py/path-injection` query only considers `FileSystemAccess` APIs,
 * so in
 *
 * ```python
 * os.system("mv " + tmp_path + " " + "%s/%s" % (upload_dir, name))
 * subprocess.call(["mv", tmp_path, os.path.join(upload_dir, name)])
 * ```
 *
 * a user-controlled `name` containing `../` is not reported as a path traversal.
 * The first form is reported by `py/command-injection`, but quoting the command
 * (for example with `shlex.quote`) does not prevent the traversal. The second
 * form is not reported by either query.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts

/**
 * Holds if `s` starts with the name of a command that reads, writes, moves,
 * copies, deletes or changes the permissions of the files named by its arguments.
 */
bindingset[s]
private predicate isFileCommandPrefix(string s) {
  s.regexpMatch("(?s)\\s*(\\S*/)?(mv|cp|cat|rm|ln|touch|mkdir|rmdir|chmod|chown|head|tail|install|rsync|tar|unzip|zip|gzip|gunzip|dd|tee)(\\s.*)?")
}

/** Gets the left-most string literal used to build the string `e`, if any. */
private StringLiteral leadingStringLiteral(Expr e) {
  result = e
  or
  result = leadingStringLiteral(e.(BinaryExpr).getLeft())
  or
  result = e.(Fstring).getValue(0)
}

/**
 * A command string that is interpreted by a shell and starts with a file-system
 * command, such as the argument to `os.system("mv " + src + " " + dst)`.
 */
private class ShellFileCommandString extends DataFlow::Node {
  ShellFileCommandString() {
    exists(SystemCommandExecution exec, DataFlow::Node cmd |
      cmd = exec.getCommand() and
      exec.isShellInterpreted(cmd) and
      this = cmd.getALocalSource() and
      isFileCommandPrefix(leadingStringLiteral(this.asExpr()).getText())
    )
  }
}

/**
 * Holds if `sink` is a file path passed to an operating system command that
 * accesses the file system.
 */
predicate isShellFileCommandPathSink(DataFlow::Node sink) {
  // A shell command string such as `"mv " + src + " " + dst`.
  exists(ShellFileCommandString cmd |
    sink = cmd and
    not cmd.asExpr() instanceof StringLiteral
  )
  or
  // An argument in an argument list such as `["mv", src, dst]`.
  exists(SystemCommandExecution exec, SequenceNode args, int i |
    exec.getCommand().asCfgNode() = args.getElement(0) and
    isFileCommandPrefix(args.getElement(0).getNode().(StringLiteral).getText()) and
    i > 0 and
    sink.asCfgNode() = args.getElement(i)
  )
}
