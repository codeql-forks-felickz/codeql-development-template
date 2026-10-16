/**
 * Provides classes for modeling database writes and reads of passwords and private
 * data through the MongoDB driver, Mongoose models and Sequelize models.
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

/**
 * A non-empty string literal stored in a field whose name suggests a password or
 * private data, such as `{ username: "admin", password: "admin" }`. Values that look
 * like password hashes or hex digests are excluded.
 */
class HardcodedSensitiveValue extends DataFlow::ValueNode {
  override StringLiteral astNode;

  HardcodedSensitiveValue() {
    exists(string v | v = astNode.getValue() |
      v != "" and
      not v.regexpMatch("\\$(2[abxy]?|argon2(i|d|id)?|pbkdf2[^$]*|scrypt|[156])\\$.*") and
      not v.regexpMatch("[0-9a-fA-F]{32,}")
    ) and
    exists(DataFlow::PropWrite pw |
      pw.getRhs().getALocalSource() = this and
      isSensitiveFieldName(pw.getPropertyName())
    )
  }
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

/**
 * A model definition of an object-document or object-relational mapper, whose
 * attribute definitions may declare sensitive paths.
 */
abstract class OrmModelDefinition extends DataFlow::Node {
  /** Gets a reference to the model defined here. */
  abstract DataFlow::SourceNode getAModelRef();

  /** Gets the object literal defining the attributes of the model, if it can be resolved. */
  abstract DataFlow::ObjectLiteralNode getAttributes();

  /** Holds if the model has a hook or plugin that may transform documents before they are written. */
  abstract predicate hasWriteHook();

  /** Gets a document (or array of documents) written through a reference to this model. */
  abstract DataFlow::Node getADocument();

  /**
   * Gets a record (or array of records) read through a reference to this model, by a
   * query that does not restrict the returned attributes.
   */
  abstract DataFlow::Node getARecord();

  /** Holds if the attribute `name` is excluded from query results unless selected explicitly. */
  predicate isHiddenByDefault(string name) { none() }

  /**
   * Holds if the attribute `name` holds a password or private data and is included in
   * records returned by queries on this model.
   */
  predicate hasExposedSensitivePath(string name) {
    exists(this.getAttributes().getAPropertyWrite(name)) and
    isSensitiveFieldName(name) and
    not this.isHiddenByDefault(name)
  }

  /**
   * Holds if the attributes cannot be resolved, or the model may transform documents
   * before they are written, for example by hashing passwords in a hook.
   */
  predicate mayTransformOnWrite() {
    not exists(this.getAttributes())
    or
    this.hasWriteHook()
  }

  /** Holds if the attribute `name` has a custom setter, which may hash the value. */
  predicate hasSetter(string name) {
    exists(
      this.getAttributes()
          .getAPropertyWrite(name)
          .getRhs()
          .getALocalSource()
          .(DataFlow::ObjectLiteralNode)
          .getAPropertyWrite("set")
    )
  }

  /** Holds if the attribute `name` is sensitive and stored as provided. */
  predicate hasClearTextSensitivePath(string name) {
    exists(this.getAttributes().getAPropertyWrite(name)) and
    isSensitiveFieldName(name) and
    not this.hasSetter(name) and
    not this.mayTransformOnWrite()
  }
}

/** Gets a call to `mongoose.model` or `connection.model`. */
private API::InvokeNode mongooseModelCall() {
  result =
    ModelOutput::getATypeNode(["mongoose", "mongoose.Connection"])
        .getMember("model")
        .getAnInvocation()
}

/** Gets a reference to the Mongoose model looked up by `mongoose.model(name)`, tracked by `t`. */
private DataFlow::SourceNode mongooseModelLookup(string name, DataFlow::TypeTracker t) {
  t.start() and
  exists(API::InvokeNode call | call = mongooseModelCall() and result = call |
    call.getNumArgument() = 1 and
    name = call.getArgument(0).getStringValue()
  )
  or
  exists(DataFlow::TypeTracker t2 | result = mongooseModelLookup(name, t2).track(t2, t))
}

/** A call to `mongoose.model(name, schema)` or `connection.model(name, schema)`. */
class MongooseModelDefinition extends OrmModelDefinition instanceof API::InvokeNode {
  MongooseModelDefinition() {
    this = mongooseModelCall() and
    super.getNumArgument() >= 2
  }

  override DataFlow::SourceNode getAModelRef() {
    result = [super.getReturn(), super.getInstance()].getAValueReachableFromSource()
    or
    // A later lookup of the same model by name, such as `mongoose.model('User')`.
    result =
      mongooseModelLookup(super.getArgument(0).getStringValue(), DataFlow::TypeTracker::end())
  }

  /** Gets the schema object passed to this call. */
  DataFlow::SourceNode getSchema() { result = super.getArgument(1).getALocalSource() }

  override DataFlow::ObjectLiteralNode getAttributes() {
    result = this.getSchema().(DataFlow::NewNode).getArgument(0).getALocalSource()
  }

  override predicate hasWriteHook() { exists(this.getSchema().getAMethodCall(["pre", "plugin"])) }

  override DataFlow::Node getADocument() {
    exists(DataFlow::SourceNode model | model = this.getAModelRef() |
      result = model.getAnInstantiation().getArgument(0)
      or
      result = model.getAMethodCall(["create", "insertMany"]).getArgument(0)
      or
      result =
        model
            .getAMethodCall([
                "update", "updateOne", "updateMany", "replaceOne", "findOneAndUpdate",
                "findByIdAndUpdate", "findOneAndReplace"
              ])
            .getArgument(1)
    )
  }

  override predicate isHiddenByDefault(string name) {
    this.getAttributes()
        .getAPropertyWrite(name)
        .getRhs()
        .getALocalSource()
        .(DataFlow::ObjectLiteralNode)
        .getAPropertyWrite("select")
        .getRhs()
        .mayHaveBooleanValue(false)
  }

  /** Gets a call that reads records through this model. */
  private DataFlow::MethodCallNode getAReadCall() {
    result =
      this.getAModelRef()
          .getAMethodCall([
              "find", "findOne", "findById", "findOneAndUpdate", "findByIdAndUpdate",
              "findOneAndDelete", "findByIdAndDelete", "findOneAndReplace", "findOneAndRemove",
              "findByIdAndRemove"
            ])
  }

  /** Gets `read` or a query obtained by chaining methods onto it. */
  private DataFlow::MethodCallNode getAQuery(DataFlow::MethodCallNode read) {
    read = this.getAReadCall() and result = read
    or
    result =
      this.getAQuery(read)
          .getAMethodCall([
              "exec", "sort", "limit", "skip", "lean", "populate", "where", "equals", "orFail",
              "session", "collation", "hint", "setOptions"
            ])
  }

  /** Holds if the query started by `read` restricts the returned fields. */
  private predicate hasProjection(DataFlow::MethodCallNode read) {
    read.getMethodName() = ["find", "findOne", "findById"] and
    exists(DataFlow::Node arg | arg = read.getArgument(1) |
      not arg.getALocalSource() instanceof DataFlow::FunctionNode
    )
    or
    exists(
      read.getAnArgument().getALocalSource().getAPropertyWrite(["projection", "select", "fields"])
    )
    or
    exists(this.getAQuery(read).getAMethodCall(["select", "projection"]))
  }

  override DataFlow::Node getARecord() {
    exists(DataFlow::MethodCallNode read, DataFlow::MethodCallNode query |
      query = this.getAQuery(read) and
      not this.hasProjection(read)
    |
      result = query.getLastArgument().getALocalSource().(DataFlow::FunctionNode).getParameter(1)
      or
      result = query.getAMethodCall("then").getABoundCallbackParameter(0, 0)
      or
      exists(AwaitExpr await |
        await.getOperand().flow().getALocalSource() = query and result = await.flow()
      )
    )
  }
}

/** Gets a Sequelize hook method that runs before rows are written. */
private string sequelizeWriteHook() {
  result =
    [
      "addHook", "hook", "beforeCreate", "beforeBulkCreate", "beforeSave", "beforeUpdate",
      "beforeBulkUpdate", "beforeUpsert", "beforeValidate"
    ]
}

/**
 * A Sequelize model, defined either by a class extending `Model` that is initialized
 * with `Model.init(attributes, options)`, or by `sequelize.define(name, attributes, options)`.
 */
abstract class SequelizeModelDefinition extends OrmModelDefinition {
  /** Gets the options object passed when defining the model. */
  abstract DataFlow::SourceNode getOptions();

  override predicate hasWriteHook() {
    exists(this.getOptions().getAPropertyWrite("hooks"))
    or
    exists(this.getAModelRef().getAMethodCall(sequelizeWriteHook()))
  }

  override DataFlow::Node getADocument() {
    exists(DataFlow::SourceNode model | model = this.getAModelRef() |
      result = model.getAnInstantiation().getArgument(0)
      or
      result =
        model.getAMethodCall(["create", "build", "bulkCreate", "upsert", "update"]).getArgument(0)
    )
  }

  /** Gets a call that reads records through this model without restricting its attributes. */
  private DataFlow::MethodCallNode getAReadCall() {
    result =
      this.getAModelRef()
          .getAMethodCall([
              "findAll", "findOne", "findByPk", "findOrCreate", "findAndCountAll", "findCreateFind"
            ]) and
    not exists(result.getAnArgument().getALocalSource().getAPropertyWrite("attributes")) and
    not exists(this.getOptions().getAPropertyWrite("defaultScope"))
  }

  override DataFlow::Node getARecord() {
    exists(DataFlow::MethodCallNode read | read = this.getAReadCall() |
      result = read.getAMethodCall("then").getABoundCallbackParameter(0, 0)
      or
      exists(AwaitExpr await |
        await.getOperand().flow().getALocalSource() = read and result = await.flow()
      )
    )
  }
}

/** A class extending Sequelize's `Model`, initialized with `Model.init(attributes, options)`. */
class SequelizeClassModelDefinition extends SequelizeModelDefinition instanceof DataFlow::ClassNode {
  SequelizeClassModelDefinition() {
    super.getASuperClassNode() =
      ModelOutput::getATypeNode("sequelize.Model").getAValueReachableFromSource()
  }

  /** Gets a call to `init` on this model. */
  private DataFlow::MethodCallNode getAnInitCall() {
    result = super.getAClassReference().getAMethodCall("init")
  }

  override DataFlow::SourceNode getAModelRef() { result = super.getAClassReference() }

  override DataFlow::ObjectLiteralNode getAttributes() {
    result = this.getAnInitCall().getArgument(0).getALocalSource()
  }

  override DataFlow::SourceNode getOptions() {
    result = this.getAnInitCall().getArgument(1).getALocalSource()
  }
}

/** A call to `sequelize.define(name, attributes, options)`. */
class SequelizeDefineModelDefinition extends SequelizeModelDefinition instanceof API::CallNode {
  SequelizeDefineModelDefinition() {
    this = ModelOutput::getATypeNode("sequelize.Sequelize").getMember("define").getACall()
  }

  override DataFlow::SourceNode getAModelRef() {
    result = super.getReturn().getAValueReachableFromSource()
  }

  override DataFlow::ObjectLiteralNode getAttributes() {
    result = super.getArgument(1).getALocalSource()
  }

  override DataFlow::SourceNode getOptions() { result = super.getArgument(2).getALocalSource() }
}

/** Holds if `doc` is a document written through the model defined by `def`. */
private predicate ormModelDocument(DataFlow::Node doc, OrmModelDefinition def) {
  doc = def.getADocument()
}

/** Holds if `doc` is a document that is persisted to a database. */
private predicate persistedDocument(DataFlow::Node doc) {
  mongoCollectionDocument(doc) or ormModelDocument(doc, _)
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
      not exists(OrmModelDefinition def | ormModelDocument(doc, def) |
        def.mayTransformOnWrite() or def.hasSetter(field)
      )
    )
  }

  override string getASensitiveField() { result = field and isSensitiveFieldName(field) }
}

/**
 * A whole document, such as `req.body`, written through a Mongoose or Sequelize model
 * that declares a sensitive attribute that is not hashed or encrypted before it is saved.
 */
class OrmWholeDocumentSink extends DatabaseStorageSink {
  OrmModelDefinition def;

  OrmWholeDocumentSink() {
    ormModelDocument(this, def) and
    not this.getALocalSource() instanceof DataFlow::ObjectLiteralNode and
    def.hasClearTextSensitivePath(_)
  }

  override string getASensitiveField() { def.hasClearTextSensitivePath(result) }
}
