/**
 * @name Encoded secret written to workflow log
 * @description Printing a secret after encoding or transforming it (for example with `base64`)
 *              defeats the runner's log masking and exposes the secret in the workflow log.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id actions/credential-and-data-exposure
 * @tags actions
 *       security
 *       external/cwe/cwe-532
 */

import actions

/** Holds if `expr` is an Actions expression that evaluates to a secret value. */
bindingset[expr]
predicate isSecretExpression(string expr) {
  exists(string expressionWithoutLiterals |
    expressionWithoutLiterals =
      expr.regexpReplaceAll("\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'", "") and
    expressionWithoutLiterals
        .regexpMatch("(?s).*(^|[^A-Za-z0-9_.])(secrets(\\s*\\.\\s*[A-Za-z_][A-Za-z0-9_]*|\\s*\\[[^]]+\\])?|github\\s*\\.\\s*token)([^A-Za-z0-9_]|$).*") and
    not expressionWithoutLiterals.regexpMatch("(?s).*(==|!=|<=|>=|<|>|&&).*") and
    not expressionWithoutLiterals.regexpMatch("(?s)^\\s*!.*") and
    not expressionWithoutLiterals.regexpMatch("(?s).*\\b(contains|startsWith|endsWith)\\s*\\(.*")
  )
}

/** Holds if `offset` points to a shell pipeline separator in `stmt`. */
bindingset[stmt]
private predicate isPipelineSeparator(string stmt, int offset) {
  exists(string pipe | pipe = stmt.regexpFind("\\|", _, offset)) and
  not exists(string protectedSpan, int spanOffset |
    protectedSpan =
      stmt.regexpFind("\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|\\$\\{\\{.*?\\}\\}", _,
        spanOffset) and
    spanOffset <= offset and
    offset < spanOffset + protectedSpan.length()
  ) and
  (offset = 0 or stmt.substring(offset - 1, offset) != "\\") and
  (offset = 0 or stmt.substring(offset - 1, offset) != "|") and
  (offset + 1 >= stmt.length() or stmt.substring(offset + 1, offset + 2) != "|")
}

/** Gets the offset of pipeline separator `k` in `stmt`. */
bindingset[stmt]
private int getPipelineSeparatorOffset(string stmt, int k) {
  result = rank[k + 1](int offset | isPipelineSeparator(stmt, offset) | offset)
}

/** Gets a stage of the pipeline in `stmt`, ignoring quoted pipes and Actions expressions. */
bindingset[stmt]
string getStage(string stmt, int k) {
  exists(string command |
    command = stmt.regexpReplaceAll("\\$\\([^()]*\\)|`[^`]*`", "") and
    (
      k = 0 and
      (
        exists(int end |
          getPipelineSeparatorOffset(command, 0) = end and
          result = command.substring(0, end).trim()
        )
        or
        not exists(int end | getPipelineSeparatorOffset(command, 0) = end) and
        result = command.trim()
      )
      or
      k > 0 and
      exists(int start |
        getPipelineSeparatorOffset(command, k - 1) = start and
        (
          exists(int end |
            getPipelineSeparatorOffset(command, k) = end and
            result = command.substring(start + 1, end).trim()
          )
          or
          not exists(int end | getPipelineSeparatorOffset(command, k) = end) and
          result = command.substring(start + 1, command.length()).trim()
        )
      )
    )
  )
}

/** Holds if `stage` is a command whose output is an encoded or transformed form of its input. */
bindingset[stage]
predicate isEncodingCommand(string stage) {
  stage
      .regexpMatch("(sudo\\s+)?(\\S*/)?(base64|base32|basenc|xxd|od|hexdump|rev|uuencode|openssl\\s+(base64|enc))(\\s.*)?")
}

/** Holds if `stage` forwards its input to the log unchanged. */
bindingset[stage]
predicate isPassThroughCommand(string stage) {
  stage.regexpMatch("^(sudo\\s+)?(\\S*/)?tee(\\s.*)?")
  or
  stage
      .regexpMatch("^(sudo\\s+)?(\\S*/)?(cat|fold)(\\s+(-|-[a-zA-Z0-9][a-zA-Z0-9-]*(\\s+[0-9]+)?))*\\s*$")
}

/** Holds if `stage` consumes secret arguments without forwarding them to stdout. */
bindingset[stage]
predicate isNonEmittingCommand(string stage) {
  stage.regexpMatch("^(sudo\\s+)?(\\S*/)?curl(\\s.*)?")
}

/** Holds if `stage` redirects its standard output to a file. */
bindingset[stage]
predicate redirectsStdout(string stage) { stage.regexpMatch(".*(^|[^2])>{1,2}\\s*[^&\\s].*") }

/** Gets the name of a shell variable or environment variable referenced in `stage`. */
bindingset[stage]
string getAReferencedVariable(string stage) {
  result =
    stage
        .regexpReplaceAll("'(?:\\\\.|[^'\\\\])*'", "")
        .regexpReplaceAll("\\\\\\$", "")
        .regexpFind("\\$\\{?[a-zA-Z_][a-zA-Z0-9_]*", _, _)
        .regexpCapture("\\$\\{?(.*)", 1)
  or
  result =
    stage
        .regexpReplaceAll("'(?:\\\\.|[^'\\\\])*'", "")
        .regexpCapture("(?:\\S*/)?printenv\\s+([a-zA-Z_][a-zA-Z0-9_]*).*", 1)
}

/** Holds if `stage` in `run` references the secret expression `secret`. */
bindingset[run, useLine, stage]
predicate stageReferencesSecret(Run run, int useLine, string stage, Expression secret) {
  isSecretExpression(secret.getExpression()) and
  (
    // inline secret expression: echo "${{ secrets.X }}" | base64
    secret = run.getAnScriptExpr() and
    stage.indexOf(secret.getRawExpression()) >= 0
    or
    exists(string var |
      var = getAReferencedVariable(stage) and
      stageReferencesVariableSecret(run, run.getScript(), useLine, var, secret)
    )
  )
}

/** Holds if a referenced variable resolves to a secret in its environment or latest assignment. */
bindingset[run, script, useLine, var]
predicate stageReferencesVariableSecret(
  Run run, ShellScript script, int useLine, string var, Expression secret
) {
  isSecretExpression(secret.getExpression()) and
  (
    // environment variable: env: { X: ${{ secrets.X }} }
    secret = run.getInScopeEnvVarExpr(var)
    or
    // shell variable assigned from a secret: X="${{ secrets.X }}" or X="$SECRET_ENV"
    (
      secret = run.getAnScriptExpr() and
      getLatestAssignmentData(script, useLine, var).indexOf(secret.getRawExpression()) >= 0
      or
      secret =
        run.getInScopeEnvVarExpr(getAReferencedVariable(getLatestAssignmentData(script, useLine, var)))
    )
  )
}

/** Gets the data for the latest assignment to `var` before `useLine`. */
bindingset[script, useLine, var]
private string getLatestAssignmentData(ShellScript script, int useLine, string var) {
  exists(int assignmentLine, string assignmentStmt |
    assignmentStmt = script.getStmt(assignmentLine) and
    assignmentLine < useLine and
    script.getAssignment(assignmentLine, var, result) and
    not exists(int laterAssignmentLine, string laterStmt |
      laterStmt = script.getStmt(laterAssignmentLine) and
      script.getAssignment(laterAssignmentLine, var, _) and
      assignmentLine < laterAssignmentLine and
      laterAssignmentLine < useLine
    )
  )
}

/** Holds if `stage` provides the secret to the input of encoding stage `encodingStage`. */
bindingset[run, useLine, stageIndex, encodingStage, stage]
predicate stageProducesSecret(
  Run run, int useLine, int stageIndex, int encodingStage, string stage, Expression secret
) {
  stageReferencesSecret(run, useLine, stage, secret) and
  (
    stageIndex < encodingStage and not isNonEmittingCommand(stage)
    or
    stageIndex = encodingStage and stage.regexpMatch(".*<<<\\s*.*")
  )
}

from Run run, int i, string stmt, int j, Expression secret
where
  run.getScript() instanceof BashShellScript and
  stmt = run.getScript().getStmt(i) and
  // the statement is not the body of a command substitution, e.g. X="$(echo "$S" | base64)"
  not exists(string outer | outer = run.getScript().getStmt(i) |
    outer.indexOf("$(" + stmt + ")") >= 0 or
    outer.indexOf("`" + stmt + "`") >= 0
  ) and
  // the output is not captured in a variable
  not stmt.regexpMatch("^(export\\s+|local\\s+|declare\\s+)?[a-zA-Z0-9_]+=.*") and
  isEncodingCommand(getStage(stmt, j)) and
  // the secret flows into the encoding command
  exists(int k | k <= j | stageProducesSecret(run, i, k, j, getStage(stmt, k), secret)) and
  not exists(int k | k < j | redirectsStdout(getStage(stmt, k))) and
  not exists(int k | k < j | isNonEmittingCommand(getStage(stmt, k))) and
  // the encoded value reaches the log
  forall(int l | l > j and exists(getStage(stmt, l)) | isPassThroughCommand(getStage(stmt, l))) and
  not exists(int l | l >= j | redirectsStdout(getStage(stmt, l)))
select run.getScript(),
  "The secret $@ is encoded and printed to the workflow log, which bypasses secret masking.",
  secret, secret.getExpression()
