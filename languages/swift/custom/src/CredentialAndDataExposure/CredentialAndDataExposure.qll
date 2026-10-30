/**
 * Provides models and flow steps that extend the standard Swift credential and
 * data exposure queries (`swift/hardcoded-key`, `swift/static-initialization-vector`,
 * `swift/cleartext-transmission`, `swift/cleartext-storage-database`).
 *
 * The Swift CodeQL libraries do not support data extensions, so these models are
 * written in QL and plugged into the extension points (`*Sink`,
 * `*AdditionalFlowStep`, `SinkModelCsv`) exposed by the standard libraries.
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.ExternalFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.security.SensitiveExprs
import codeql.swift.security.HardcodedEncryptionKeyExtensions
import codeql.swift.security.StaticInitializationVectorExtensions
import codeql.swift.security.CleartextTransmissionExtensions
import codeql.swift.security.CleartextStorageDatabaseExtensions

/**
 * Sinks for the CommonCrypto C API, which is not modeled by the standard
 * `swift/hardcoded-key` and `swift/static-initialization-vector` queries.
 */
private class CommonCryptoSinks extends SinkModelCsv {
  override predicate row(string row) {
    row =
      [
        // CCCrypt(op, alg, options, key, keyLength, iv, dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved)
        ";;false;CCCrypt(_:_:_:_:_:_:_:_:_:_:_:);;;Argument[3];encryption-key",
        ";;false;CCCrypt(_:_:_:_:_:_:_:_:_:_:_:);;;Argument[5];encryption-iv",
        // CCCryptorCreate(op, alg, options, key, keyLength, iv, cryptorRef)
        ";;false;CCCryptorCreate(_:_:_:_:_:_:_:);;;Argument[3];encryption-key",
        ";;false;CCCryptorCreate(_:_:_:_:_:_:_:);;;Argument[5];encryption-iv",
        // CCCryptorCreateWithMode(op, mode, alg, padding, iv, key, keyLength, tweak, tweakLength, numRounds, options, cryptorRef)
        ";;false;CCCryptorCreateWithMode(_:_:_:_:_:_:_:_:_:_:_:_:);;;Argument[4];encryption-iv",
        ";;false;CCCryptorCreateWithMode(_:_:_:_:_:_:_:_:_:_:_:_:);;;Argument[5];encryption-key"
      ]
  }
}

/** Holds if `e` is a reference to the variable or property `v`. */
predicate refersTo(Expr e, VarDecl v) {
  e.(DeclRefExpr).getDecl() = v
  or
  e.(MemberRefExpr).getMember() = v
}

/**
 * Holds if `v` is a stored property or a global variable, that is, a variable
 * that is not local to a function or closure.
 */
predicate isNonLocalVar(VarDecl v) {
  not v instanceof ParamDecl and
  not exists(v.getEnclosingCallable())
}

/**
 * Gets `e` or an expression wrapped by `e` through implicit conversions, explicit
 * casts, `!`, `try` or parentheses.
 */
Expr stripWrappers(Expr e) {
  result = e
  or
  result = stripWrappers(e.getUnconverted())
  or
  result = stripWrappers(e.(ExplicitCastExpr).getSubExpr())
  or
  result = stripWrappers(e.(ForceValueExpr).getSubExpr())
  or
  result = stripWrappers(e.(AnyTryExpr).getSubExpr())
  or
  result = stripWrappers(e.(ParenExpr).getSubExpr())
}

/**
 * A field-insensitive jump step from a value written to a stored property or
 * global variable (`obj.prop = value`) to any read of that property elsewhere
 * in the program.
 *
 * The standard data flow library only tracks such flow when the object itself
 * can be followed from the write to the read. That is not possible for objects
 * held in static/global properties (whose initializers have no control flow
 * graph) or for objects that are handed to UIKit and later called back, such as
 * view controllers configured before being presented.
 */
predicate storedPropertyJumpStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
  exists(AssignExpr assign, VarDecl v |
    isNonLocalVar(v) and
    refersTo(assign.getDest(), v) and
    nodeFrom.asExpr() = assign.getSource() and
    refersTo(nodeTo.asExpr(), v) and
    not nodeTo.asExpr() = any(AssignExpr a).getDest()
  )
}

/**
 * A taint step from the receiver of `withUnsafeBytes` (for example on `Data`)
 * into the buffer parameter of the closure passed to it, for example from
 * `key` to `keyBytes` in `key.withUnsafeBytes { keyBytes in ... }`.
 */
predicate withUnsafeBytesStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
  exists(CallExpr call, ClosureExpr closure |
    call.getStaticTarget().(Function).getName() =
      ["withUnsafeBytes(_:)", "withUnsafeMutableBytes(_:)"] and
    closure = call.getArgument(0).getExpr().getUnconverted() and
    nodeFrom.asExpr() = call.getQualifier() and
    nodeTo.asExpr() = closure.getParam(0).getAnAccess()
  )
}

/**
 * A taint step from a raw buffer pointer to its `baseAddress`, for example from
 * `keyBytes` to `keyBytes.baseAddress`.
 */
predicate baseAddressStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
  exists(MemberRefExpr member |
    member.getMember().(VarDecl).getName() = "baseAddress" and
    nodeFrom.asExpr() = member.getBase() and
    nodeTo.asExpr() = member
  )
}

/** Holds if there is a CommonCrypto-related additional taint step from `nodeFrom` to `nodeTo`. */
predicate cryptoMaterialStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
  storedPropertyJumpStep(nodeFrom, nodeTo) or
  withUnsafeBytesStep(nodeFrom, nodeTo) or
  baseAddressStep(nodeFrom, nodeTo)
}

private class HardcodedKeyCryptoMaterialStep extends HardcodedEncryptionKeyAdditionalFlowStep {
  override predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    cryptoMaterialStep(nodeFrom, nodeTo)
  }
}

private class StaticIvCryptoMaterialStep extends StaticInitializationVectorAdditionalFlowStep {
  override predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    cryptoMaterialStep(nodeFrom, nodeTo)
  }
}

/** Holds if `e` is a string, byte array or number literal. */
private predicate isHardcodedLiteral(Expr e) {
  e instanceof StringLiteralExpr or
  e instanceof ArrayExpr or
  e instanceof NumberLiteralExpr
}

/**
 * Holds if `e` is a hard-coded value that originates from the literal `origin`.
 * That is, either `e` is the literal itself, or `e` reads a global variable or
 * stored property that is never reassigned and whose initializer is hard-coded.
 */
predicate isHardcodedValue(Expr e, Expr origin) {
  isHardcodedLiteral(e) and origin = e
  or
  exists(VarDecl v |
    refersTo(e, v) and
    isNonLocalVar(v) and
    not refersTo(any(AssignExpr a).getDest(), v) and
    isHardcodedValue(stripWrappers(v.getParentInitializer()), origin)
  )
}

/**
 * A data flow node that holds a hard-coded value that the standard data flow
 * library cannot see, because it originates from a global variable or a
 * property initializer, neither of which has a control flow graph.
 *
 * This covers:
 * - reads of non-local constants whose initializer is a literal, such as
 *   `aesKey` in `fileprivate let aesKey = "..."`; and
 * - parameters that receive such a value from a call that itself lives in a
 *   property initializer, such as `key` in
 *   `static let instance = AESCrypto(key: aesKey, iv: iv)`.
 */
class HardcodedNonLocalValue extends DataFlow::Node {
  Expr origin;

  HardcodedNonLocalValue() {
    isHardcodedValue(this.asExpr(), origin) and
    not isHardcodedLiteral(this.asExpr())
    or
    exists(CallExpr call, int i, Expr arg |
      not exists(DataFlow::Node n | n.asExpr() = call) and
      arg = call.getArgument(i).getExpr() and
      isHardcodedValue(stripWrappers(arg), origin) and
      this.(DataFlow::ParameterNode).asParameter() = call.getStaticTarget().getParam(i)
    )
  }

  /** Gets the hard-coded literal this value originates from. */
  Expr getOrigin() { result = origin }
}

/** Holds if `s` is a `struct` declared in the analyzed source code. */
private predicate isSourceStruct(StructDecl s) {
  exists(s.getLocation().getFile().getRelativePath())
}

/**
 * Holds if `call` constructs a value of a `struct` declared in the analyzed
 * source code, for example by calling the implicit memberwise initializer of a
 * request model such as `struct SignInModel { let email: String; let password: String }`.
 */
private predicate isSourceStructConstruction(CallExpr call) {
  exists(StructDecl s | isSourceStruct(s) |
    call.getStaticTarget().(Initializer).getEnclosingDecl().asNominalTypeDecl() = s
    or
    call instanceof InitializerCallExpr and
    call.getType().getUnderlyingType().(NominalType).getDeclaration() = s
  )
}

/**
 * A taint step from an argument of an initializer of a source-declared `struct`
 * to the constructed value. This makes a request model that wraps a password
 * (for example an Alamofire `parameters:` value) sensitive as a whole.
 */
predicate modelStructInitializerStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
  exists(CallExpr call |
    isSourceStructConstruction(call) and
    (
      exists(Initializer initializer, int i |
        call.getStaticTarget() = initializer and
        nodeFrom.asExpr() = call.getArgument(i).getExpr() and
        (
          not initializer.hasBody()
          or
          exists(AssignExpr assign, MemberRefExpr dest |
            assign.getDest() = dest and
            dest.getBase().(DeclRefExpr).getDecl() = initializer.getSelfParam() and
            DataFlow::localFlow(
              DataFlow::parameterNode(initializer.getParam(i)),
              DataFlow::exprNode(assign.getSource())
            )
          )
        )
      )
      or
      (
        not exists(call.getStaticTarget().(Initializer)) and
        nodeFrom.asExpr() = call.getAnArgument().getExpr()
      )
    ) and
    nodeTo.asExpr() = call
  )
}

private class ModelStructTransmissionStep extends CleartextTransmissionAdditionalFlowStep {
  override predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    modelStructInitializerStep(nodeFrom, nodeTo)
  }
}

/** A call to `NSEntityDescription.insertNewObject(forEntityName:into:)`. */
class CoreDataInsertNewObjectCall extends CallExpr {
  CoreDataInsertNewObjectCall() {
    this.getStaticTarget()
        .(Method)
        .hasQualifiedName("NSEntityDescription", "insertNewObject(forEntityName:into:)")
  }
}

/**
 * Holds if `e` is a value given to the variable `v`, either as its initializer,
 * through an assignment `v = e`, or through an optional binding such as
 * `if let v = e` or `guard let v = e`.
 */
predicate isAssignedValue(VarDecl v, Expr e) {
  e = stripWrappers(v.getParentInitializer())
  or
  exists(AssignExpr assign |
    stripWrappers(assign.getDest()).(DeclRefExpr).getDecl() = v and
    e = stripWrappers(assign.getSource())
  )
  or
  exists(ConditionElement cond, Pattern p |
    p = cond.getPattern() and
    e = stripWrappers(cond.getInitializer()) and
    (
      p.(NamedPattern).getVarDecl() = v or
      p.(OptionalSomePattern).getSubPattern().(NamedPattern).getVarDecl() = v
    )
  )
}

/** Holds if `e` refers to the local variable `v`, possibly through an `&` (inout) expression. */
predicate refersToLocal(Expr e, VarDecl v) {
  stripWrappers(e).(DeclRefExpr).getDecl() = v
  or
  stripWrappers(e).(InOutExpr).getSubExpr().(DeclRefExpr).getDecl() = v
}

/**
 * Holds if `e` evaluates to a Core Data object created with
 * `NSEntityDescription.insertNewObject(forEntityName:into:)`, either directly or
 * through local variables that are initialized, assigned or bound to it, as in
 * `user = NSEntityDescription.insertNewObject(...) as? User; if let user = user { ... }`.
 */
private predicate isInsertedCoreDataObject(Expr e) {
  stripWrappers(e) instanceof CoreDataInsertNewObjectCall
  or
  exists(VarDecl v, Expr value |
    stripWrappers(e).(DeclRefExpr).getDecl() = v and
    isAssignedValue(v, value) and
    isInsertedCoreDataObject(value)
  )
}

/**
 * A value assigned to a property of a Core Data object created with
 * `NSEntityDescription.insertNewObject(forEntityName:into:)`, for example
 * `password` in `user.password = password`.
 *
 * The standard `swift/cleartext-storage-database` query only recognizes such
 * writes when the static type of the object resolves to a subclass of
 * `NSManagedObject`. This sink recognizes the Core Data factory call directly,
 * so it also applies when the managed object class cannot be resolved (for
 * example when it is generated by Xcode from the data model).
 */
class CoreDataInsertedObjectWrite extends CleartextStorageDatabaseSink {
  CoreDataInsertedObjectWrite() {
    exists(AssignExpr assign, MemberRefExpr dest |
      assign.getDest() = dest and
      isInsertedCoreDataObject(dest.getBase()) and
      this.asExpr() = assign.getSource() and
      // avoid duplicating the standard `NSManagedObject` sink
      not dest.getBase().getFullyConverted().getType().getUnderlyingType().getABaseType*().getName() =
        "NSManagedObject"
    )
  }
}

/**
 * A value assigned to a property of an Objective-C Realm object, that is, an
 * instance of a class derived from `RLMObject`, for example `cardNumber` in
 * `creditInfo.cardNumber = cardNumber`.
 *
 * The standard `swift/cleartext-storage-database` query only models Realm Swift
 * (`RealmSwiftObject`) objects.
 */
class RealmObjcObjectWrite extends CleartextStorageDatabaseSink {
  RealmObjcObjectWrite() {
    exists(AssignExpr assign, MemberRefExpr dest |
      assign.getDest() = dest and
      dest.getBase().getFullyConverted().getType().getUnderlyingType().getABaseType*().getName() =
        "RLMObject" and
      not dest.getBase().(DeclRefExpr).getDecl() instanceof SelfParamDecl and
      this.asExpr() = assign.getSource()
    )
  }
}

/**
 * A hard-coded value that is assigned to a property with a sensitive name, for
 * example `"secret"` in `user.password = "secret"`. Such a value is sensitive even
 * though it is not read from a variable with a sensitive name.
 */
class HardcodedSensitivePropertyValue extends DataFlow::Node {
  HardcodedSensitivePropertyValue() {
    exists(AssignExpr assign |
      assign.getDest() instanceof SensitiveExpr and
      this.asExpr() = assign.getSource() and
      isHardcodedValue(stripWrappers(assign.getSource()), _)
    )
  }
}

/**
 * Gets `name` without a trailing user interface widget suffix, for example
 * `ssn` for `ssnField` or `cardNumber` for `cardNumberTextField`.
 */
bindingset[name]
private string stripUiSuffix(string name) {
  result = name.regexpReplaceAll("(?i)(text)?(field|tf|txt|input|box|textview|entry)$", "")
}

/**
 * Gets a regular expression for abbreviated payment and identity data names
 * that the standard heuristics do not match, such as `ccNo`, `cvv` or `pin`.
 */
private string abbreviatedSensitiveNameRegexp() {
  result = "(?i)((cc|card).?(no|num(ber)?)|cv[vc]2?|pin(.?(code|no|num(ber)?))?|ssn)"
}

/**
 * A reference to a user interface input (such as a `UITextField` outlet) whose
 * name, without its widget suffix, indicates sensitive data, for example
 * `ssnField`, `ccNoTextField`, `cvvTextField`, `pinTextField` or `passcodeTF`.
 * The standard heuristics do not match such names when the sensitive part is
 * not delimited or is abbreviated.
 */
class SensitiveUiInputExpr extends Expr {
  SensitiveUiInputExpr() {
    exists(VarDecl v, string stripped |
      refersTo(this, v) and
      stripped = stripUiSuffix(v.getName()) and
      stripped != v.getName() and
      stripped != "" and
      (
        stripped.regexpMatch(any(SensitiveDataType t).getRegexp()) or
        stripped.regexpMatch(abbreviatedSensitiveNameRegexp())
      ) and
      not stripped.regexpMatch(HeuristicNames::notSensitiveRegexp())
    ) and
    not this instanceof SensitiveExpr
  }
}

/**
 * A taint step from a value in a dictionary or array literal to the literal,
 * and from the argument of a JSON serialization call to its result, for example
 * from `ssnField.text` to `jsonData` in
 * `JSONSerialization.data(withJSONObject: ["ssn": ssnField.text])`.
 */
predicate serializedPayloadStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
  exists(DictionaryExpr dict |
    nodeFrom.asExpr() = dict.getAnElement().(TupleExpr).getElement(1) and
    nodeTo.asExpr() = dict
  )
  or
  exists(ArrayExpr array |
    nodeFrom.asExpr() = array.getAnElement() and
    nodeTo.asExpr() = array
  )
  or
  exists(CallExpr call |
    (
      call.getStaticTarget()
          .(Method)
          .hasQualifiedName("JSONSerialization", "data(withJSONObject:options:)")
      or
      call.getStaticTarget().(Method).hasQualifiedName("JSONEncoder", "encode(_:)")
    ) and
    nodeFrom.asExpr() = call.getArgument(0).getExpr() and
    nodeTo.asExpr() = call
  )
}

private class SerializedPayloadTransmissionStep extends CleartextTransmissionAdditionalFlowStep {
  override predicate step(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    serializedPayloadStep(nodeFrom, nodeTo)
  }
}

/** A call to an initializer of `URLRequest` (or its Objective-C counterparts) that takes a URL. */
class UrlRequestInitCall extends CallExpr {
  UrlRequestInitCall() {
    this.getStaticTarget()
        .(Method)
        .hasQualifiedName(["URLRequest", "NSURLRequest", "NSMutableURLRequest"],
          ["init(url:)", "init(url:cachePolicy:timeoutInterval:)"])
  }

  /** Gets the URL argument of this call. */
  Expr getUrlArgument() { result = this.getArgument(0).getExpr() }
}

/**
 * A call to a `URLSession` method that creates a data or upload task with a
 * completion handler, for example `session.dataTask(with: request) { data, response, error in ... }`.
 */
class UrlSessionTaskCall extends CallExpr {
  UrlSessionTaskCall() {
    this.getStaticTarget()
        .(Method)
        .hasQualifiedName("URLSession",
          [
            "dataTask(with:)", "dataTask(with:completionHandler:)", "uploadTask(with:from:)",
            "uploadTask(with:from:completionHandler:)"
          ])
  }

  /** Gets the request or URL argument of this call. */
  Expr getRequestArgument() { result = this.getArgument(0).getExpr() }

  /** Gets the completion handler closure of this call, if any. */
  ClosureExpr getCompletionHandler() {
    result = this.getArgumentWithLabel("completionHandler").getExpr().getUnconverted()
  }
}

/** Holds if `e` is a string literal for a cleartext `http://` URL. */
private predicate isCleartextHttpUrlLiteral(Expr e) {
  e.(StringLiteralExpr).getValue().regexpMatch("(?i)http://.+")
}

/**
 * A taint-tracking configuration from cleartext `http://` URL literals to the
 * URL of a `URLRequest` or the request of a `URLSession` task.
 */
private module CleartextHttpUrlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    isCleartextHttpUrlLiteral(node.asExpr())
    or
    isCleartextHttpUrlLiteral(node.(HardcodedNonLocalValue).getOrigin())
  }

  predicate isSink(DataFlow::Node node) {
    node.asExpr() = any(UrlRequestInitCall init).getUrlArgument()
    or
    node.asExpr() = any(UrlSessionTaskCall call).getRequestArgument()
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    storedPropertyJumpStep(nodeFrom, nodeTo)
    or
    exists(UrlRequestInitCall init |
      nodeFrom.asExpr() = init.getUrlArgument() and
      nodeTo.asExpr() = init
    )
  }
}

private module CleartextHttpUrlFlow = TaintTracking::Global<CleartextHttpUrlConfig>;

/** Holds if `e` is a URL or request that targets a cleartext `http://` URL. */
predicate isCleartextHttpTarget(Expr e) { CleartextHttpUrlFlow::flowTo(DataFlow::exprNode(e)) }

/**
 * A value assigned as the body of a request to a cleartext `http://` URL, for
 * example `jsonData` in
 * `var request = URLRequest(url: URL(string: "http://...")!); request.httpBody = jsonData`.
 */
class CleartextHttpBodySink extends CleartextTransmissionSink {
  CleartextHttpBodySink() {
    exists(AssignExpr assign, MemberRefExpr dest, UrlRequestInitCall init |
      assign.getDest() = dest and
      dest.getMember().(VarDecl).getName() = ["httpBody", "HTTPBody"] and
      DataFlow::localFlow(DataFlow::exprNode(init), DataFlow::exprNode(dest.getBase())) and
      isCleartextHttpTarget(init.getUrlArgument()) and
      this.asExpr() = assign.getSource()
    )
  }
}

/**
 * The response data received by the completion handler of a `URLSession` task
 * whose request targets a cleartext `http://` URL, for example `data` in
 * `session.dataTask(with: request) { data, response, error in ... }`.
 */
class CleartextHttpResponseData extends DataFlow::Node {
  CleartextHttpResponseData() {
    exists(UrlSessionTaskCall call |
      isCleartextHttpTarget(call.getRequestArgument()) and
      this.asExpr() = call.getCompletionHandler().getParam(0).getAnAccess()
    )
  }
}
