/**
 * @name Password stored or checked in cleartext or with a fast hash
 * @description Storing a password in cleartext, comparing a submitted password directly
 *              against a stored password, or hashing a password with a fast message
 *              digest (such as MD5 or SHA-1) exposes user credentials if the password
 *              store is ever read by an attacker.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id java/credential-and-data-exposure
 * @tags security
 *       external/cwe/cwe-256
 *       external/cwe/cwe-916
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.QueryInjection
import semmle.code.java.security.Sanitizers

/** Holds if `name` looks like the name of a variable or field holding a password. */
bindingset[name]
predicate isPasswordName(string name) {
  (
    name.regexpMatch("(?i).*(passw(or)?d|passphrase|passcode|pwd).*")
    or
    // `pass`, `user_pass`, `adminpass`, `userPass`
    name.regexpMatch("(?i)(.*[^a-z])?pass")
    or
    name.regexpMatch("(?i)(admin|user|db|new|old|current|login|confirm)pass")
    or
    name.regexpMatch(".*[a-z0-9]Pass")
  ) and
  not name.regexpMatch("(?i).*(hash|crypt|digest|salt|encod|question|hint|policy|expir|reset|length|param|field|label|key).*")
}

/** Holds if `sql` is SQL text that refers to a password column. */
bindingset[sql]
predicate mentionsPasswordColumn(string sql) {
  sql.regexpMatch("(?is).*\\b(passw(or)?d|passwd|pwd|pass|passcode|passphrase)\\b.*")
}

/** A compile-time string constant that names a password, such as `"password"`. */
class PasswordNameConstant extends CompileTimeConstantExpr {
  PasswordNameConstant() { isPasswordName(this.getStringValue()) }
}

/**
 * A call that reads a submitted password from untrusted input, such as
 * `request.getParameter("password")` or `params.get("password")`.
 */
class SubmittedPasswordRead extends MethodCall {
  SubmittedPasswordRead() {
    this.getAnArgument() instanceof PasswordNameConstant and
    (
      this = any(ActiveThreatModelSource s).asExpr()
      or
      exists(ActiveThreatModelSource s |
        DataFlow::localFlow(s, DataFlow::exprNode(this.getQualifier()))
      )
    )
  }
}

/** Holds if `e` is a protected password value. */
predicate isProtectedPasswordValue(Expr e) {
  exists(PasswordProtectingCall protection |
    e = protection or DataFlow::localExprFlow(protection, e)
  )
}

/** Holds if a password parameter has a caller that passes a protected value. */
predicate hasProtectedPasswordCaller(Parameter parameter) {
  isPasswordName(parameter.getName()) and
  exists(Call c, Expr arg |
    c.getCallee().getSourceDeclaration() = parameter.getCallable() and
    arg = c.getArgument(parameter.getPosition()) and
    isProtectedPasswordValue(arg)
  )
}

/** A parameter whose name indicates that it holds a password. */
class PasswordParameter extends Parameter {
  PasswordParameter() {
    isPasswordName(this.getName()) and
    not hasProtectedPasswordCaller(this) and
    // Avoid duplicate paths: only start at the outermost parameter of a call chain.
    not exists(Call c, Expr arg |
      c.getCallee().getSourceDeclaration() = this.getCallable() and
      arg = c.getArgument(this.getPosition())
    |
      isPasswordName(arg.(VarAccess).getVariable().getName())
      or
      arg instanceof SubmittedPasswordRead
    )
  }
}

/**
 * A call that reads a password from storage, such as `user.getPassword()`,
 * `rs.getString("password")` or `repo.findPasswordByName(name)`.
 */
class StoredPasswordRead extends MethodCall {
  StoredPasswordRead() {
    not this instanceof SubmittedPasswordRead and
    (
      exists(string name | name = this.getMethod().getName() |
        name.regexpMatch("(?i)(get|find|load|fetch|read|lookup|select|query)\\w*(passw(or)?d|pwd)\\w*") and
        not name.regexpMatch("(?i).*(hash|crypt|digest|salt|encod).*")
      )
      or
      this.getMethod().hasName(["get", "getString", "getObject"]) and
      this.getArgument(0) instanceof PasswordNameConstant
    )
  }
}

/** A call that hashes, encrypts or otherwise protects its input. */
class PasswordProtectingCall extends MethodCall {
  PasswordProtectingCall() {
    exists(string name | name = this.getMethod().getName() |
      name.regexpMatch("(?i).*(hash|crypt|digest|kdf|argon|pbkdf).*") and
      not name = "hashCode"
    )
    or
    this.getMethod().hasName("encode") and
    this.getMethod().getDeclaringType().getASupertype*().getName().matches("%PasswordEncoder")
  }
}

/** Gets an expression that is the SQL text of a query that refers to a password column. */
Expr passwordSqlText() {
  result = any(QueryInjectionSink s).asExpr() and
  exists(CompileTimeConstantExpr lit |
    mentionsPasswordColumn(lit.getStringValue()) and
    TaintTracking::localExprTaint(lit, result)
  )
}

/** Holds if `e` is an argument that is hashed with a fast general-purpose hash function. */
predicate isFastHashInput(Expr e) {
  exists(MethodCall mc, Method m | mc.getMethod() = m and e = mc.getArgument(0) |
    m.getDeclaringType().getASupertype*().hasQualifiedName("java.security", "MessageDigest") and
    m.hasName(["update", "digest"])
    or
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "DigestUtils") and
    m.getName().regexpMatch("(md2|md5|sha|sha1|sha224|sha256|sha384|sha512|sha3_\\d+)(Hex)?")
    or
    m.getDeclaringType().hasQualifiedName("org.springframework.util", "DigestUtils") and
    m.getName().matches("%md5%")
    or
    m.getDeclaringType().getASupertype*().hasQualifiedName("com.google.common.hash", "HashFunction") and
    m.getName().matches("hash%")
  )
}

/**
 * Holds if `node` is a sink where a password is used without a password-hashing
 * function, with `message` describing the problem.
 */
predicate passwordSink(DataFlow::Node node, string message) {
  // Plaintext password embedded in, or bound as a parameter of, a SQL statement
  // that reads or writes a password column.
  exists(Expr sql | sql = passwordSqlText() |
    node.asExpr() = sql
    or
    exists(Call c, int i, int j |
      c.getArgument(i) = sql and j > i and node.asExpr() = c.getArgument(j)
    )
    or
    exists(MethodCall prepare, MethodCall set |
      prepare.getArgument(0) = sql and
      prepare.getMethod().hasName("prepareStatement") and
      DataFlow::localExprFlow(prepare, set.getQualifier()) and
      set.getMethod().getName().matches("set%") and
      node.asExpr() = set.getArgument(1)
    )
  ) and
  message =
    "This $@ is used in a SQL statement on a password column without being hashed, so passwords are stored in cleartext."
  or
  // Plaintext password persisted through a JPA entity.
  exists(MethodCall set |
    set.getMethod().getName().regexpMatch("(?i)set(passw(or)?d|pwd|passcode|passphrase)") and
    set.getMethod()
        .getDeclaringType()
        .getSourceDeclaration()
        .getAnAnnotation()
        .getType()
        .hasQualifiedName(["javax.persistence", "jakarta.persistence"], "Entity") and
    node.asExpr() = set.getArgument(0)
  ) and
  message =
    "This $@ is persisted in a JPA entity without being hashed, so passwords are stored in cleartext."
  or
  // Submitted password compared directly against a stored password.
  exists(MethodCall eq, Expr other, StoredPasswordRead stored |
    eq.getMethod().hasName(["equals", "equalsIgnoreCase", "contentEquals"]) and
    eq.getMethod().getDeclaringType() instanceof TypeString and
    (
      node.asExpr() = eq.getQualifier() and other = eq.getArgument(0)
      or
      node.asExpr() = eq.getArgument(0) and other = eq.getQualifier()
    )
    or
    eq.getMethod().hasQualifiedName("java.util", "Objects", "equals") and
    (
      node.asExpr() = eq.getArgument(0) and other = eq.getArgument(1)
      or
      node.asExpr() = eq.getArgument(1) and other = eq.getArgument(0)
    )
  |
    DataFlow::localExprFlow(stored, other)
  ) and
  message =
    "This $@ is compared directly with a stored password, which indicates that passwords are stored in cleartext."
  or
  isFastHashInput(node.asExpr()) and
  message =
    "This $@ is hashed with a fast hash function, which is insufficient for password storage. Use a password-hashing function such as bcrypt, scrypt, Argon2 or PBKDF2."
}

module CredentialExposureConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asParameter() instanceof PasswordParameter
    or
    source.asExpr() instanceof SubmittedPasswordRead
    or
    exists(Parameter parameter, Call c, VarAccess arg |
      hasProtectedPasswordCaller(parameter) and
      c.getCallee().getSourceDeclaration() = parameter.getCallable() and
      arg = c.getArgument(parameter.getPosition()) and
      isPasswordName(arg.getVariable().getName()) and
      not isProtectedPasswordValue(arg) and
      source.asExpr() = arg and
      not passwordSink(source, _)
    )
  }

  predicate isSink(DataFlow::Node sink) { passwordSink(sink, _) }

  predicate isBarrier(DataFlow::Node node) {
    node.asExpr() instanceof PasswordProtectingCall or
    node instanceof SimpleTypeSanitizer
  }

  predicate isBarrierOut(DataFlow::Node node) { isFastHashInput(node.asExpr()) }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    isSink(node) and
    c.getAReadContent() instanceof DataFlow::ArrayContent
  }
}

module CredentialExposureFlow = TaintTracking::Global<CredentialExposureConfig>;

import CredentialExposureFlow::PathGraph

from CredentialExposureFlow::PathNode source, CredentialExposureFlow::PathNode sink, string message
where
  CredentialExposureFlow::flowPath(source, sink) and
  passwordSink(sink.getNode(), message)
select sink.getNode(), source, sink, message, source.getNode(), "password"
