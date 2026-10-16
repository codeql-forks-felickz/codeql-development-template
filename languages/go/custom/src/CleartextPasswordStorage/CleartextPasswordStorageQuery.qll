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
      "(?is).*(hint|policy|length|len|min|max|count|reset|expir|changed|updated|strength|rule|field|label|url|required|enabled|salt|hash|digest|kdf|bcrypt|scrypt|argon|pbkdf).*"
  }

  /** Holds if `name` looks like the name of a clear-text password. */
  bindingset[name]
  private predicate isPasswordName(string name) {
    name.regexpMatch(maybePassword()) and
    not name.regexpMatch(notPassword()) and
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
      this.getTarget().getPackage().getPath().regexpMatch("(crypto|golang\\.org/x/crypto)(/.*)?")
      or
      this.getCalleeName()
          .regexpMatch("(?i).*(hash|digest|crypt|derive|kdf|argon|scrypt|pbkdf|sha\\d|md5).*")
    }
  }

  /** A node holding a value that is not a clear-text password. */
  private class NonCleartextPassword extends DataFlow::Node {
    NonCleartextPassword() {
      exists(DataFlow::Node hashed | TaintTracking::localTaint(hashed, this) |
        hashed = any(HashCall c).getResult(_)
        or
        hashed.(DataFlow::SsaNode).getSourceVariable().getName().regexpMatch(notPassword())
      )
    }
  }

  /** A read of a variable, parameter or field whose name suggests it holds a password. */
  private class PasswordReadSource extends Source {
    string name;

    PasswordReadSource() {
      isPasswordName(name) and
      isStringLike(this.getType()) and
      (
        this.(DataFlow::SsaNode).getSourceVariable().getName() = name
        or
        exists(DataFlow::FieldReadNode fr | fr = this |
          fr.getFieldName() = name and
          // the field was not overwritten with a hashed value in the same function
          not exists(Write w, NonCleartextPassword ncp |
            w.writesField(_, fr.getField(), ncp) and
            w.getRoot() = fr.getRoot()
          )
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
    result = "(?is)\\s*(insert|update|replace|merge|upsert)\\b.*"
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
        this = c.getSyntacticArgument(any(int i | i >= firstArg))
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
