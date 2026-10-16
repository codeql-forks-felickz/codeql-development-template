/**
 * @name Hard-coded password stored on an application account
 * @description Creating or updating an Active Record model with a password taken
 *              from a string literal (for example in `db/seeds.rb`) ships a
 *              source-controlled default credential that anyone can use.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id rb/hardcoded-account-password
 * @tags security
 *       external/cwe/cwe-259
 *       external/cwe/cwe-798
 *       external/cwe/cwe-1392
 */

import codeql.ruby.AST
import codeql.ruby.Concepts
import codeql.ruby.DataFlow
import codeql.ruby.CFG

/**
 * Holds if `name` is the name of a model attribute that holds a clear-text
 * account password (but not a confirmation, digest or encrypted copy of it).
 */
bindingset[name]
predicate isPasswordAttributeName(string name) {
  name.regexpMatch("(?i)(.*_)?(password|passwd|passcode|passphrase|pwd)") and
  not name.regexpMatch("(?i).*(crypt|hash|digest|sha|md5).*")
}

/**
 * Holds if the persistent write `w` writes `value` to the model attribute `name`.
 */
predicate attributeWrite(PersistentWriteAccess w, string name, DataFlow::Node value) {
  value = w.getValue() and
  (
    // User.create(password: "x")
    value = w.(DataFlow::CallNode).getKeywordArgument(name)
    or
    // User.create({ password: "x" })
    exists(CfgNodes::ExprNodes::PairCfgNode pair |
      pair =
        w.(DataFlow::CallNode)
            .getArgument(_)
            .asExpr()
            .(CfgNodes::ExprNodes::HashLiteralCfgNode)
            .getAKeyValuePair() and
      pair.getKey().getConstantValue().getStringlikeValue() = name and
      value.asExpr() = pair.getValue()
    )
    or
    // user.update_attribute(:password, "x")
    w.(DataFlow::CallNode).getMethodName() = "update_attribute" and
    w.(DataFlow::CallNode).getArgument(0).getConstantValue().getStringlikeValue() = name
    or
    // user.password = "x"
    exists(DataFlow::CallNode setter |
      setter.asExpr().getExpr() instanceof SetterMethodCall and
      setter.getArgument(0) = w and
      setter.getMethodName() = name + "="
    )
  )
}

/** Holds if `f` looks like test code, which does not create deployed accounts. */
predicate isTestFile(File f) {
  f.getRelativePath()
      .regexpMatch("(?i)(.*/)?(test|tests|spec|specs|features|fixtures)/.*|.*_(test|spec)\\.rb")
}

from PersistentWriteAccess w, string name, DataFlow::Node value, StringLiteral pw
where
  attributeWrite(w, name, value) and
  isPasswordAttributeName(name) and
  pw = value.getALocalSource().asExpr().getExpr() and
  pw.getConstantValue().getString() != "" and
  not isTestFile(pw.getLocation().getFile())
select pw, "Hard-coded password stored in the '" + name + "' attribute of an application account."
