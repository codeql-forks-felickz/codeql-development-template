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
  s.regexpMatch("(?s)\\s*(.*/)?(mv|cp|cat|rm|ln|touch|mkdir|rmdir|chmod|chown|head|tail|install|rsync|tar|unzip|zip|gzip|gunzip|dd|tee)(\\s.*)?")
}

bindingset[executable]
private string fileCommandName(string executable) {
  result =
    executable
        .regexpCapture("(?s).*/?(mv|cp|cat|rm|ln|touch|mkdir|rmdir|chmod|chown|head|tail|install|rsync|tar|unzip|zip|gzip|gunzip|dd|tee)(\\s.*)?$",
          1)
}

private predicate isPathValuedOption(string option) { option in ["-t", "-C", "-d", "-o"] }

bindingset[command, option]
private predicate isFlagWithoutValue(string command, string option) {
  option in [
      "-f", "-i", "-n", "-r", "-R", "-v", "-p", "-a", "-b", "-e", "-E", "-s", "-t", "-T", "-u",
      "-x", "-z", "-j", "-P", "-L", "-H", "-h", "-Z", "-k", "-q", "-w", "--", "--help", "--version"
    ] and
  not isPathValuedOption(option) and
  not (command in ["head", "tail"] and option in ["-n", "-c"])
}

private predicate isOptionFlag(SequenceNode args, int i) {
  args.getElement(i).getNode().(StringLiteral).getText().regexpMatch("(?s)^-.*")
}

bindingset[args, i]
private predicate isPathOptionValue(SequenceNode args, int i) {
  i > 1 and
  exists(string option |
    option = args.getElement(i - 1).getNode().(StringLiteral).getText() and
    isOptionFlag(args, i - 1) and
    isPathValuedOption(option)
  )
}

bindingset[args, command, i]
private predicate isNonPathOptionValue(SequenceNode args, string command, int i) {
  i > 1 and
  exists(string option |
    option = args.getElement(i - 1).getNode().(StringLiteral).getText() and
    isOptionFlag(args, i - 1) and
    not isPathValuedOption(option) and
    not isFlagWithoutValue(command, option)
  )
}

bindingset[args, command, i]
private predicate isPositionalArgument(SequenceNode args, string command, int i) {
  i > 0 and
  not isOptionFlag(args, i) and
  not isNonPathOptionValue(args, command, i) and
  not isPathOptionValue(args, i)
}

bindingset[args, command, i]
private predicate isFirstModeOrOwnerArgument(SequenceNode args, string command, int i) {
  command in ["chmod", "chown"] and
  isPositionalArgument(args, command, i) and
  not exists(int previous |
    previous in [1 .. i - 1] and isPositionalArgument(args, command, previous)
  )
}

bindingset[command, prefix]
private predicate isShellOptionValue(string command, string prefix) {
  exists(string option |
    option = prefix.regexpCapture("(?s).*\\s(-[^\\s]+)\\s*$", 1) and
    not isPathValuedOption(option) and
    not isFlagWithoutValue(command, option)
  )
}

private predicate before(AstNode earlier, AstNode later) {
  earlier.getLocation().getStartLine() < later.getLocation().getStartLine()
  or
  earlier.getLocation().getStartLine() = later.getLocation().getStartLine() and
  earlier.getLocation().getStartColumn() < later.getLocation().getStartColumn()
}

private StringLiteral previousStringLiteral(Expr command, Expr operand) {
  result = command.getASubExpression*() and
  before(result, operand) and
  not exists(StringLiteral later |
    later = command.getASubExpression*() and
    before(result, later) and
    before(later, operand)
  )
}

/** Gets the prefix before a positional `%s` formatting argument. */
bindingset[format, index]
private string formatPrefixBeforeArgument(string format, int index) {
  index >= 0 and
  result = format.regexpCapture("(?s)((?:.*?%s){" + index.toString() + "}.*?)%s.*", 1)
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

/** Gets the left-most string literal used to build the string `e`, if any. */
private StringLiteral leadingStringLiteral(Expr e) {
  result = e
  or
  result = leadingStringLiteral(e.(BinaryExpr).getLeft())
  or
  result = e.(Fstring).getValue(0)
}

private predicate isShellConcatOperand(Expr command, Expr operand) {
  exists(BinaryExpr add |
    add.getOp() instanceof Add and
    command.getASubExpression*() = add and
    operand = add.getASubExpression() and
    not operand instanceof StringLiteral and
    not operand instanceof BinaryExpr and
    not operand instanceof Fstring
  )
}

private predicate isShellFormatOperand(Expr command, Expr operand, StringLiteral format, int index) {
  exists(BinaryExpr formatted |
    formatted.getOp() instanceof Mod and
    formatted.getLeft() = format and
    command.getASubExpression*() = formatted and
    (
      exists(Tuple args | args = formatted.getRight() and args.getElt(index) = operand)
      or
      index = 0 and
      not formatted.getRight() instanceof Tuple and
      formatted.getRight() = operand
    )
  )
}

private predicate hasShellSeparatorBefore(Expr command, Expr operand) {
  exists(StringLiteral literal |
    literal = command.getASubExpression*() and
    before(literal, operand) and
    literal.getText().regexpMatch("(?s).*[;|&<>\\n].*")
  )
}

bindingset[command, operand, format, prefix]
private predicate hasShellSeparatorBeforeFormatArgument(
  Expr command, Expr operand, StringLiteral format, string prefix
) {
  prefix.regexpMatch("(?s).*[;|&<>\\n].*")
  or
  exists(StringLiteral literal |
    literal = command.getASubExpression*() and
    literal != format and
    before(literal, operand) and
    literal.getText().regexpMatch("(?s).*[;|&<>\\n].*")
  )
}

/**
 * Holds if `sink` is a file path passed to an operating system command that
 * accesses the file system.
 */
predicate isShellFileCommandPathSink(DataFlow::Node sink) {
  exists(ShellFileCommandString cmd, Expr operand, string commandName |
    commandName = fileCommandName(leadingStringLiteral(cmd.asExpr()).getText()) and
    (
      isShellConcatOperand(cmd.asExpr(), operand) and
      not hasShellSeparatorBefore(cmd.asExpr(), operand) and
      exists(StringLiteral previous |
        previous = previousStringLiteral(cmd.asExpr(), operand) and
        not isShellOptionValue(commandName, previous.getText())
      )
      or
      exists(StringLiteral format, int index, string prefix |
        isShellFormatOperand(cmd.asExpr(), operand, format, index) and
        prefix = formatPrefixBeforeArgument(format.getText(), index) and
        not hasShellSeparatorBeforeFormatArgument(cmd.asExpr(), operand, format, prefix) and
        not isShellOptionValue(commandName, prefix)
      )
    ) and
    sink.asExpr() = operand
  )
  or
  // An argument in an argument list such as `["mv", src, dst]`.
  exists(SystemCommandExecution exec, SequenceNode args, int i, string commandName |
    exec.getCommand().asCfgNode() = args.getElement(0) and
    commandName = fileCommandName(args.getElement(0).getNode().(StringLiteral).getText()) and
    isFileCommandPrefix(args.getElement(0).getNode().(StringLiteral).getText()) and
    i > 0 and
    not isOptionFlag(args, i) and
    not isNonPathOptionValue(args, commandName, i) and
    not isFirstModeOrOwnerArgument(args, commandName, i) and
    (
      isPathOptionValue(args, i)
      or
      isPositionalArgument(args, commandName, i)
    ) and
    sink.asCfgNode() = args.getElement(i)
  )
}
