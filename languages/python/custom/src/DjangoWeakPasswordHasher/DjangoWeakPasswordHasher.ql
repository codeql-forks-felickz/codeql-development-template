/**
 * @name Weak primary password hasher in Django settings
 * @description Configuring a fast or obsolete hash such as MD5 or SHA-1 as the primary
 *              Django password hasher makes stored password hashes easy to brute-force.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id py/django-weak-password-hasher
 * @tags security
 *       external/cwe/cwe-916
 *       external/cwe/cwe-328
 */

import python

/**
 * Holds if `name` is a Django password hasher class that uses a fast or obsolete
 * algorithm that is unsuitable for password storage.
 */
bindingset[name]
predicate isWeakHasherName(string name) {
  name.regexpMatch("(.*\\.)?(Unsalted)?(MD5|SHA1)PasswordHasher|(.*\\.)?CryptPasswordHasher")
}

/** Holds if `f` looks like a test-only settings file. */
predicate isTestFile(File f) {
  f.getRelativePath().regexpMatch("(?i)(.*/)?(tests?|testing)/.*") or
  f.getShortName().regexpMatch("(?i)(tests?_.*|.*_tests?|.*_testing)\\.py")
}

from AssignStmt assign, Name target, Expr hashers, StringLiteral primary
where
  assign.getScope() instanceof Module and
  target = assign.getATarget() and
  target.getId() = "PASSWORD_HASHERS" and
  hashers = assign.getValue() and
  (
    primary = hashers.(List).getElt(0)
    or
    primary = hashers.(Tuple).getElt(0)
  ) and
  isWeakHasherName(primary.getText()) and
  not isTestFile(assign.getLocation().getFile())
select target,
  "PASSWORD_HASHERS uses $@ as the primary hasher, which is too fast for password storage.",
  primary, primary.getText()
