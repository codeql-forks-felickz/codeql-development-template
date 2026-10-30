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
  expr.regexpMatch("(?is).*\\b(secrets\\b|github\\.token\\b).*")
}

/** Gets a stage of the pipeline in `stmt`, ignoring pipes nested in command substitutions. */
bindingset[stmt]
string getStage(string stmt, int k) {
  result = stmt.regexpReplaceAll("\\$\\([^()]*\\)|`[^`]*`", "").splitAt("|", k).trim()
}

/** Holds if `stage` is a command whose output is an encoded or transformed form of its input. */
bindingset[stage]
predicate isEncodingCommand(string stage) {
  stage
      .regexpMatch("(sudo\\s+)?(\\S*/)?(base64|base32|basenc|xxd|od|hexdump|rev|uuencode|openssl\\s+(base64|enc))(\\s.*)?")
}

/** Holds if `stage` forwards its input to the log unchanged. */
bindingset[stage]
predicate isPassThroughCommand(string stage) { stage.regexpMatch("(tee|cat|fold)(\\s.*)?") }

/** Holds if `stage` redirects its standard output to a file. */
bindingset[stage]
predicate redirectsStdout(string stage) { stage.regexpMatch(".*(^|[\\s1&])>{1,2}\\s*[^&\\s].*") }

/** Gets the name of a shell variable or environment variable referenced in `stage`. */
bindingset[stage]
string getAReferencedVariable(string stage) {
  result = stage.regexpFind("\\$\\{?[a-zA-Z_][a-zA-Z0-9_]*", _, _).regexpCapture("\\$\\{?(.*)", 1)
  or
  result = stage.regexpCapture("(?:\\S*/)?printenv\\s+([a-zA-Z_][a-zA-Z0-9_]*).*", 1)
}

/** Holds if `stage` in `run` references the secret expression `secret`. */
bindingset[stage]
predicate stageReferencesSecret(Run run, string stage, Expression secret) {
  isSecretExpression(secret.getExpression()) and
  (
    // inline secret expression: echo "${{ secrets.X }}" | base64
    secret = run.getAnScriptExpr() and
    stage.indexOf(secret.getRawExpression()) >= 0
    or
    exists(string var | var = getAReferencedVariable(stage) |
      // environment variable: env: { X: ${{ secrets.X }} }
      secret = run.getInScopeEnvVarExpr(var)
      or
      // shell variable assigned from a secret: X="${{ secrets.X }}" or X="$SECRET_ENV"
      exists(string data | run.getScript().getAnAssignment(var, data) |
        secret = run.getAnScriptExpr() and
        data.indexOf(secret.getRawExpression()) >= 0
        or
        secret = run.getInScopeEnvVarExpr(getAReferencedVariable(data))
      )
    )
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
  exists(int k | k <= j | stageReferencesSecret(run, getStage(stmt, k), secret)) and
  // the encoded value reaches the log
  forall(int l | l > j and exists(getStage(stmt, l)) | isPassThroughCommand(getStage(stmt, l))) and
  not exists(int l | l >= j | redirectsStdout(getStage(stmt, l)))
select run.getScript(),
  "The secret $@ is encoded and printed to the workflow log, which bypasses secret masking.",
  secret, secret.getExpression()
