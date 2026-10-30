/**
 * Provides a taint-tracking configuration for reasoning about passwords that
 * are written to a database without first being hashed with a password
 * hashing function.
 */

import go
private import semmle.go.security.SensitiveActions::HeuristicNames as HeuristicNames

/**
 * Provides sources, sinks and barriers for clear-text storage of passwords in
 * a database.
 */
module CleartextPasswordStorage {
  /** A data-flow source of a clear-text password. */
  abstract class Source extends DataFlow::Node {
    Source() {
      // hard-coded strings are uninteresting
      not exists(this.getStringValue())
    }

    /** Gets a string that describes this source. */
    abstract string describe();
  }

  /** A data-flow sink where a value is written to a database. */
  abstract class Sink extends DataFlow::Node { }

  /** A barrier for clear-text storage of passwords, such as a password hash. */
  abstract class Barrier extends DataFlow::Node { }

  /** Gets a regular expression matching names that may refer to a password. */
  string maybePassword() { result = "(?is).*pass(wd|word|code|phrase)(?!.*question).*" }

  /**
   * Gets a regular expression matching names that refer to password metadata or
   * to an already hashed or encrypted password, rather than to a clear-text password.
   */
  string notPassword() {
    result =
      "(?is)(.*_)?(hint|policy|length|len|min|max|count|reset|expir\\w*|changed|updated|strength|rule|field|label|url|required|enabled|salt|hash\\w*|digest|kdf|bcrypt|scrypt|argon\\w*|pbkdf\\w*)(_.*)?"
  }

  /** Splits camel-case and snake-case identifiers into lower-case words. */
  bindingset[name]
  private string nameWords(string name) {
    result =
      name.regexpReplaceAll("([A-Z]+)([A-Z][a-z])", "$1_$2")
          .regexpReplaceAll("([a-z0-9])([A-Z])", "$1_$2")
          .toLowerCase()
  }

  /** Holds if `name` looks like the name of a clear-text password. */
  bindingset[name]
  private predicate isPasswordName(string name) {
    name.regexpMatch(maybePassword()) and
    not nameWords(name).regexpMatch(notPassword()) and
    not name.regexpMatch(HeuristicNames::notSensitive())
  }

  /** Holds if `t` is a string or byte-slice type, possibly via a named type. */
  private predicate isStringLike(Type t) {
    t.getUnderlyingType() instanceof StringType or
    t.getUnderlyingType() instanceof ByteSliceType
  }

  /** The result of a call that hashes, derives a key from, or encrypts its input. */
  private class HashCall extends DataFlow::CallNode {
    HashCall() {
      not this.getCalleeName().regexpMatch("(?i).*(decrypt|open|unseal).*") and
      (
        this.getCalleeName()
            .regexpMatch("(?i).*(hash|digest|derivekey|kdf|argon|scrypt|pbkdf|sha\\d+|md5|encrypt|seal).*")
        or
        this.getTarget().getPackage().getPath().regexpMatch("crypto/(sha\\d+|md5)") and
        this.getCalleeName().regexpMatch("Sum[0-9_]*")
        or
        this.getTarget().getPackage().getPath() = "golang.org/x/crypto/bcrypt" and
        this.getCalleeName() = "GenerateFromPassword"
        or
        this.getTarget()
            .getPackage()
            .getPath()
            .regexpMatch("(crypto|golang\\.org/x/crypto)/(scrypt|argon2|pbkdf2|hkdf)") and
        this.getCalleeName() = ["Key", "IDKey", "New", "Extract", "Expand"]
      )
    }
  }

  /** Taint-preserving transformations, stopping at concatenations for operand-wise checks. */
  private predicate protectedLocalFlow(DataFlow::Node origin, DataFlow::Node destination) {
    TaintTracking::localTaint(origin, destination) and
    not exists(AddExpr addition |
      DataFlow::exprNode(addition) != origin and
      TaintTracking::localTaint(origin, DataFlow::exprNode(addition.getAnOperand())) and
      TaintTracking::localTaint(DataFlow::exprNode(addition), destination)
    )
  }

  /** A node holding a value that is not a clear-text password. */
  private class NonCleartextPassword extends DataFlow::Node {
    NonCleartextPassword() {
      exists(DataFlow::Node hashed | protectedLocalFlow(hashed, this) |
        hashed = any(HashCall c).getResult(_)
        or
        nameWords(hashed.(DataFlow::SsaNode).getSourceVariable().getName())
            .regexpMatch("(.*_)?(hash\\w*|digest|kdf\\w*|bcrypt|scrypt|argon\\w*|pbkdf\\w*|hkdf\\w*)(_.*)?") and
        // A hash-like name must not override operand-wise concatenation checks.
        not exists(AddExpr addition |
          TaintTracking::localTaint(DataFlow::exprNode(addition), hashed)
        )
        or
        exists(AddExpr addition |
          hashed = DataFlow::exprNode(addition) and
          forall(Expr operand | operand = addition.getAnOperand() |
            exists(DataFlow::exprNode(operand).getStringValue()) or
            DataFlow::exprNode(operand) instanceof NonCleartextPassword
          )
        )
      )
    }
  }

  /** Holds if the bases may share a receiver, including through SSA merges. */
  private predicate mayBeSameReceiver(DataFlow::Node left, DataFlow::Node right) {
    DataFlow::localFlow(left, right)
    or
    DataFlow::localFlow(right, left)
    or
    exists(DataFlow::SsaNode base |
      DataFlow::localFlow(base, left) and DataFlow::localFlow(base, right)
    )
    or
    mayBeSameReceiver(left.(DataFlow::PostUpdateNode).getPreUpdateNode(), right)
    or
    mayBeSameReceiver(left, right.(DataFlow::PostUpdateNode).getPreUpdateNode())
    or
    mayBeSameReceiver(left.(DataFlow::PointerDereferenceNode).getOperand(),
      right.(DataFlow::PointerDereferenceNode).getOperand())
  }

  /** A merged receiver cannot establish guaranteed identity for a protective write. */
  private predicate hasMergedReceiver(DataFlow::Node node) {
    exists(SsaPhiNode merged, DataFlow::Node use |
      use.asInstruction() = merged.getVariable().getAUse() and
      DataFlow::localFlow(use, node)
    )
    or
    hasMergedReceiver(node.(DataFlow::PostUpdateNode).getPreUpdateNode())
    or
    hasMergedReceiver(node.(DataFlow::PointerDereferenceNode).getOperand())
  }

  /** Holds only for receiver identities established without an ambiguous SSA merge. */
  private predicate sameReceiver(DataFlow::Node left, DataFlow::Node right) {
    mayBeSameReceiver(left, right) and
    not hasMergedReceiver(left) and
    not hasMergedReceiver(right) and
    sameReceiverStorage(left, right)
  }

  /** Pointer copies alias storage, but struct value copies do not. */
  private predicate sameReceiverStorage(DataFlow::Node left, DataFlow::Node right) {
    exists(LocalVariable variable |
      left.(DataFlow::ReadNode).reads(variable) and
      right.(DataFlow::ReadNode).reads(variable)
    )
    or
    mayBeSameReceiver(left.(DataFlow::PointerDereferenceNode).getOperand(),
      right.(DataFlow::PointerDereferenceNode).getOperand())
    or
    sameReceiverStorage(left.(DataFlow::PostUpdateNode).getPreUpdateNode(), right)
    or
    sameReceiverStorage(left, right.(DataFlow::PostUpdateNode).getPreUpdateNode())
  }

  /** A dominating protected write to this receiver, with no possible plaintext overwrite. */
  private predicate hasProtectedWrite(DataFlow::FieldReadNode read) {
    exists(Write write, DataFlow::Node base, NonCleartextPassword value |
      write.writesField(base, read.getField(), value) and
      sameReceiver(base, read.getBase()) and
      write.dominatesNode(read.asInstruction()) and
      not exists(Write overwrite, DataFlow::Node otherBase, DataFlow::Node plaintext |
        overwrite.writesField(otherBase, read.getField(), plaintext) and
        // A possible alias is enough to invalidate the protective write.
        mayBeSameReceiver(otherBase, read.getBase()) and
        sameReceiverStorage(otherBase, read.getBase()) and
        not plaintext instanceof NonCleartextPassword and
        overwrite = write.getASuccessor+() and
        read.asInstruction() = overwrite.getASuccessor+()
      )
    )
  }

  /** A read of a variable, parameter or field whose name suggests it holds a password. */
  private class PasswordReadSource extends Source {
    string name;

    PasswordReadSource() {
      isPasswordName(name) and
      isStringLike(this.getType()) and
      (
        this.(DataFlow::SsaNode).getSourceVariable().getName() = name and
        not this instanceof NonCleartextPassword
        or
        exists(DataFlow::FieldReadNode fr | fr = this |
          fr.getFieldName() = name and
          not hasProtectedWrite(fr)
        )
      )
    }

    override string describe() { result = "an access to " + name }
  }

  /** A value written to a struct field whose name suggests it holds a password. */
  private class PasswordFieldWriteSource extends Source {
    string name;

    PasswordFieldWriteSource() {
      exists(Write w, Field f | w.writesField(_, f, this) |
        name = f.getName() and
        isPasswordName(name) and
        isStringLike(f.getType()) and
        not this instanceof NonCleartextPassword and
        // reported as a `PasswordReadSource` instead
        not this instanceof PasswordReadSource
      )
    }

    override string describe() { result = "a value written to " + name }
  }

  /** A barrier from hashing or encrypting a password. */
  private class HashBarrier extends Barrier {
    HashBarrier() { this = any(HashCall c).getResult(_) }
  }

  /**
   * Holds if `m` is a database write method whose argument at `index` is a
   * document written to the database; `index = -1` means every argument.
   */
  private predicate writeMethod(Method m, int index) {
    exists(string name |
      m.hasQualifiedName(package(["gopkg.in/mgo", "github.com/globalsign/mgo"], ""), "Collection",
        name)
    |
      name = "Insert" and index = -1
      or
      name = ["Update", "UpdateId", "UpdateAll", "Upsert", "UpsertId"] and index = 1
    )
    or
    exists(string name |
      m.hasQualifiedName(package("go.mongodb.org/mongo-driver", "mongo"), "Collection", name)
    |
      name = ["InsertOne", "InsertMany"] and index = 1
      or
      name =
        [
          "UpdateOne", "UpdateMany", "UpdateByID", "ReplaceOne", "FindOneAndUpdate",
          "FindOneAndReplace"
        ] and
      index = 2
    )
    or
    exists(string name |
      m.hasQualifiedName(package(["gorm.io/gorm", "github.com/jinzhu/gorm"], ""), "DB", name)
    |
      name = ["Create", "Save", "Updates"] and index = 0
      or
      name = "Update" and index = 1
    )
  }

  /** A document argument to a NoSQL or ORM database write. */
  private class DocumentWriteSink extends Sink {
    DocumentWriteSink() {
      exists(DataFlow::MethodCallNode c, int index | writeMethod(c.getTarget(), index) |
        index = -1 and this = c.getASyntacticArgument()
        or
        this = c.getSyntacticArgument(index)
      )
    }
  }

  /**
   * Gets a regular expression matching SQL statements that write data.
   */
  private string sqlWriteStatement() {
    result = "(?is)" + sqlLeadingTrivia() + "(insert|update|replace|merge|upsert)\\b.*"
  }

  private string sqlLeadingTrivia() { result = "(?:\\s|/\\*.*?\\*/|--[^\\r\\n]*(?:\\r?\\n|$))*" }

  /** Scalars in the small UPDATE grammar; other syntax deliberately uses the fallback. */
  private string sqlScalar() {
    result = "(?:\\?|\\$[1-9][0-9]*|'(?:[^'\\\\]|'')*'|-?[0-9]+(?:\\.[0-9]+)?|[a-z_][a-z0-9_.]*)"
  }

  /**
   * Gets the SET clause of a simple, fully recognized UPDATE. No subqueries,
   * function calls, dialect-specific clauses or multiple statements are parsed,
   * so every WHERE recognized here is top-level.
   */
  bindingset[query]
  private string simpleUpdateSet(string query) {
    exists(string assignment, string comparison |
      assignment = "[a-z_][a-z0-9_.]*\\s*=\\s*" + sqlScalar() and
      comparison = sqlScalar() + "\\s*(?:=|<>|!=|<=|>=|<|>)\\s*" + sqlScalar()
    |
      result =
        query
            .regexpCapture("(?is)" + sqlLeadingTrivia() + "update\\s+[a-z_][a-z0-9_.]*\\s+set\\s+(" +
                assignment + "(?:\\s*,\\s*" + assignment + ")*)(?:\\s+where\\s+" + comparison +
                "(?:\\s+(?:and|or)\\s+" + comparison + ")*)?\\s*;?\\s*", 1)
    )
  }

  /** Maps a placeholder in SET to its zero-based argument offset. */
  bindingset[setClause]
  private int updateArgumentOffset(string setClause) {
    exists(string placeholders, string placeholder, int occurrence |
      // Quoted question marks and dollar numbers are data, not parameters.
      placeholders = setClause.regexpReplaceAll("'(?:[^'\\\\]|'')*'", "") and
      placeholder = placeholders.regexpFind("\\?|\\$[1-9][0-9]*", occurrence, _)
    |
      placeholder = "?" and result = occurrence
      or
      result = placeholder.regexpCapture("\\$([1-9][0-9]*)", 1).toInt() - 1
    )
  }

  /** A parameter argument to a `database/sql` statement that writes data. */
  private class SqlWriteArgumentSink extends Sink {
    SqlWriteArgumentSink() {
      exists(DataFlow::MethodCallNode c, string tp, string name, int firstArg |
        c.getTarget().hasQualifiedName("database/sql", tp, name)
      |
        (
          tp = ["DB", "Tx"] and name = "Exec" and firstArg = 1
          or
          tp = ["DB", "Tx", "Conn"] and name = "ExecContext" and firstArg = 2
        ) and
        // when the statement is a known constant, it must be a write
        forall(string query | query = c.getSyntacticArgument(firstArg - 1).getStringValue() |
          query.regexpMatch(sqlWriteStatement())
        ) and
        exists(int i | i >= firstArg |
          this = c.getSyntacticArgument(i) and
          forall(string query, string setClause |
            query = c.getSyntacticArgument(firstArg - 1).getStringValue() and
            setClause = simpleUpdateSet(query)
          |
            i = firstArg + updateArgumentOffset(setClause)
          )
        )
        or
        tp = "Stmt" and
        (
          name = "Exec" and firstArg = 0
          or
          name = "ExecContext" and firstArg = 1
        ) and
        this = c.getSyntacticArgument(any(int i | i >= firstArg))
      )
    }
  }

  private module Config implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof Source }

    predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

    predicate isBarrier(DataFlow::Node node) { node instanceof Barrier }

    predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

    predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
      NoSql::isAdditionalMongoTaintStep(pred, succ)
    }

    predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
      // a document written to the database stores all of its fields, map values and elements
      isSink(node) and exists(c)
    }

    predicate observeDiffInformedIncrementalMode() { any() }
  }

  /** Tracks flow from clear-text passwords to database writes. */
  module Flow = TaintTracking::Global<Config>;
}
