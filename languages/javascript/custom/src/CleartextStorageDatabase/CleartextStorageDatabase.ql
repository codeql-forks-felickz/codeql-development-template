/**
 * @name Clear text storage of sensitive information in a database
 * @description Persisting passwords or private data to a database without hashing or
 *              encryption exposes it to anyone who can read the database.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id js/clear-text-storage-of-sensitive-data-in-database
 * @tags security
 *       external/cwe/cwe-256
 *       external/cwe/cwe-311
 *       external/cwe/cwe-312
 *       external/cwe/cwe-359
 */

import javascript
import semmle.javascript.security.dataflow.CleartextStorageCustomizations
private import semmle.javascript.security.SensitiveActions

/**
 * Holds if a database field called `name` is expected to hold a password or private data.
 *
 * Secrets, certificates and account identifiers are deliberately excluded: they are
 * often stored in clear text by design (for example API tokens that must be replayed).
 */
bindingset[name]
predicate isSensitiveFieldName(string name) {
  exists(SensitiveDataClassification c |
    HeuristicNames::nameIndicatesSensitiveData(name, c) and
    c = [SensitiveDataClassification::password(), SensitiveDataClassification::private()]
  )
}

/**
 * A call whose name suggests that it hashes, encrypts or derives a key from its
 * arguments, such as `bcrypt.hash`, `argon2.hash`, `crypto.pbkdf2Sync` or `encrypt`.
 */
class HashOrEncryptCall extends DataFlow::InvokeNode {
  HashOrEncryptCall() {
    this.getCalleeName().regexpMatch("(?i).*(hash|(?<!de)crypt|digest|pbkdf|kdf|argon).*")
  }
}

/**
 * Holds if `node` is locally computed by a hash or encryption call, as in
 * `const password = await bcrypt.hash(req.body.password, 12)`.
 */
predicate isLocallyHashed(DataFlow::Node node) {
  exists(DataFlow::SourceNode src | src = node.getALocalSource() |
    src instanceof HashOrEncryptCall
    or
    src.asExpr().(AwaitExpr).getOperand().flow().getALocalSource() instanceof HashOrEncryptCall
  )
}

/** Holds if `source` is a password or private value, described by `sourceDesc`. */
predicate isSensitiveSource(DataFlow::Node source, string sourceDesc) {
  source.(SensitiveNode).getClassification() =
    [SensitiveDataClassification::password(), SensitiveDataClassification::private()] and
  sourceDesc = source.(CleartextStorage::Source).describe() and
  not isLocallyHashed(source)
}

/** Gets a reference to a MongoDB collection, tracked by `t`. */
private DataFlow::SourceNode mongoCollection(DataFlow::TypeTracker t) {
  t.start() and
  (
    result = ModelOutput::getATypeNode(["mongodb.Collection", "mongoose.Collection"]).asSource()
    or
    // `db.collection("users")` where `db` cannot be resolved to the `mongodb` package,
    // for example because it is passed in from another module.
    exists(DataFlow::MethodCallNode call | call = result |
      call.getMethodName() = "collection" and
      call.getNumArgument() = [1, 2] and
      exists(call.getArgument(0).getStringValue())
    )
  )
  or
  exists(DataFlow::TypeTracker t2 | result = mongoCollection(t2).track(t2, t))
}

/** Gets a reference to a MongoDB collection. */
private DataFlow::SourceNode mongoCollection() {
  result = mongoCollection(DataFlow::TypeTracker::end())
}

/** Holds if `doc` is a document written to a MongoDB collection. */
private predicate mongoCollectionDocument(DataFlow::Node doc) {
  exists(DataFlow::MethodCallNode call, string name |
    call = mongoCollection().getAMethodCall(name)
  |
    name = ["insert", "insertOne", "insertMany", "save"] and doc = call.getArgument(0)
    or
    name =
      ["update", "updateOne", "updateMany", "replaceOne", "findOneAndUpdate", "findOneAndReplace"] and
    doc = call.getArgument(1)
    or
    name = "findAndModify" and doc = call.getArgument(2)
  )
}

/** A call to `mongoose.model(name, schema)` or `connection.model(name, schema)`. */
class MongooseModelDefinition extends API::InvokeNode {
  MongooseModelDefinition() {
    this =
      ModelOutput::getATypeNode(["mongoose", "mongoose.Connection"])
          .getMember("model")
          .getAnInvocation() and
    this.getNumArgument() >= 2
  }

  /** Gets the API node for the model defined by this call. */
  API::Node getModel() { result = [this.getReturn(), this.getInstance()] }

  /** Gets the schema object passed to this call. */
  DataFlow::SourceNode getSchema() { result = this.getArgument(1).getALocalSource() }

  /** Gets the object literal defining the paths of the schema, if it can be resolved. */
  DataFlow::ObjectLiteralNode getSchemaDefinition() {
    result = this.getSchema().(DataFlow::NewNode).getArgument(0).getALocalSource()
  }

  /**
   * Holds if the schema cannot be resolved, or may transform documents before they
   * are written, for example by hashing passwords in a `pre('save')` hook or plugin.
   */
  predicate mayTransformOnWrite() {
    not exists(this.getSchemaDefinition())
    or
    exists(this.getSchema().getAMethodCall(["pre", "plugin"]))
  }

  /** Holds if the schema path `name` has a custom setter, which may hash the value. */
  predicate hasSetter(string name) {
    exists(
      this.getSchemaDefinition()
          .getAPropertyWrite(name)
          .getRhs()
          .getALocalSource()
          .(DataFlow::ObjectLiteralNode)
          .getAPropertyWrite("set")
    )
  }

  /** Holds if the schema path `name` is sensitive and stored as provided. */
  predicate hasClearTextSensitivePath(string name) {
    exists(this.getSchemaDefinition().getAPropertyWrite(name)) and
    isSensitiveFieldName(name) and
    not this.hasSetter(name) and
    not this.mayTransformOnWrite()
  }
}

/** Holds if `doc` is a document written through the Mongoose model defined by `def`. */
private predicate mongooseModelDocument(DataFlow::Node doc, MongooseModelDefinition def) {
  exists(API::Node model | model = def.getModel() |
    doc = model.getAnInstantiation().getArgument(0)
    or
    doc = model.getMember(["create", "insertMany"]).getACall().getArgument(0)
    or
    doc =
      model
          .getMember([
              "update", "updateOne", "updateMany", "replaceOne", "findOneAndUpdate",
              "findByIdAndUpdate", "findOneAndReplace"
            ])
          .getACall()
          .getArgument(1)
  )
}

/** Holds if `doc` is a document that is persisted to a database. */
private predicate persistedDocument(DataFlow::Node doc) {
  mongoCollectionDocument(doc) or mongooseModelDocument(doc, _)
}

/**
 * Gets an object that is part of the persisted document `doc`, that is `doc` itself,
 * a nested object (such as the operand of `$set`) or an element of an array of documents.
 */
private DataFlow::SourceNode documentObject(DataFlow::Node doc) {
  persistedDocument(doc) and
  result = doc.getALocalSource()
  or
  exists(DataFlow::SourceNode parent | parent = documentObject(doc) |
    result = parent.getAPropertyWrite().getRhs().getALocalSource() and
    result instanceof DataFlow::ObjectLiteralNode
    or
    result = parent.(DataFlow::ArrayCreationNode).getAnElement().getALocalSource()
  )
}

/** A value that is persisted to a database as clear text. */
abstract class DatabaseStorageSink extends DataFlow::Node {
  /** Gets the name of a sensitive field this value is stored in, if any. */
  abstract string getASensitiveField();
}

/** A value written to a named field of a persisted document, such as `{ password: value }`. */
class DocumentFieldSink extends DatabaseStorageSink {
  string field;

  DocumentFieldSink() {
    exists(DataFlow::Node doc |
      this = documentObject(doc).getAPropertyWrite(field).getRhs() and
      not field.charAt(0) = "$" and
      not exists(MongooseModelDefinition def | mongooseModelDocument(doc, def) |
        def.mayTransformOnWrite() or def.hasSetter(field)
      )
    )
  }

  override string getASensitiveField() { result = field and isSensitiveFieldName(field) }
}

/**
 * A whole document, such as `req.body`, written through a Mongoose model whose schema
 * declares a sensitive path that is not hashed or encrypted before it is saved.
 */
class MongooseWholeDocumentSink extends DatabaseStorageSink {
  MongooseModelDefinition def;

  MongooseWholeDocumentSink() {
    mongooseModelDocument(this, def) and
    not this.getALocalSource() instanceof DataFlow::ObjectLiteralNode and
    def.hasClearTextSensitivePath(_)
  }

  override string getASensitiveField() { def.hasClearTextSensitivePath(result) }
}

module ClearTextDatabaseStorageConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isSensitiveSource(source, _) or source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof DatabaseStorageSink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof CleartextStorage::Sanitizer or node instanceof HashOrEncryptCall
  }
}

module ClearTextDatabaseStorageFlow = TaintTracking::Global<ClearTextDatabaseStorageConfig>;

import ClearTextDatabaseStorageFlow::PathGraph

from
  ClearTextDatabaseStorageFlow::PathNode source, ClearTextDatabaseStorageFlow::PathNode sink,
  string message, string sourceDesc
where
  ClearTextDatabaseStorageFlow::flowPath(source, sink) and
  (
    isSensitiveSource(source.getNode(), sourceDesc) and
    message = "This stores sensitive data returned by $@ in a database as clear text."
    or
    // A remote value is only reported when it is stored in a sensitive field, and only
    // if no sensitive source already explains the same alert.
    sourceDesc = source.getNode().(RemoteFlowSource).getSourceType() and
    exists(sink.getNode().(DatabaseStorageSink).getASensitiveField()) and
    message =
      "This stores $@ in the sensitive database field " +
        concat(string f |
          f = sink.getNode().(DatabaseStorageSink).getASensitiveField()
        |
          "'" + f + "'", ", "
        ) + " as clear text." and
    not exists(DataFlow::Node s |
      isSensitiveSource(s, _) and ClearTextDatabaseStorageFlow::flow(s, sink.getNode())
    )
  )
select sink.getNode(), source, sink, message, source.getNode(), sourceDesc
