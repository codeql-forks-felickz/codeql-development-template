/**
 * @name Credential and sensitive data exposure in an iOS application
 * @description Sensitive data copied to the shared pasteboard, session tokens derived from
 *              credentials, missing background snapshot protection, weak keychain
 *              accessibility, cached sensitive responses and sensitive values retained in
 *              long-lived properties can all expose credentials or private information.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.5
 * @precision low
 * @id swift/credential-and-data-exposure
 * @tags security
 *       external/cwe/cwe-200
 *       external/cwe/cwe-316
 *       external/cwe/cwe-522
 *       external/cwe/cwe-922
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.security.SensitiveExprs

/** Holds if `name` looks like it holds plaintext that was decrypted from a protected store. */
bindingset[name]
private predicate isDecryptedName(string name) {
  name.regexpMatch("(?i).*(decrypt|plain.?text|clear.?text).*")
}

/** Holds if `name` indicates sensitive data, according to the standard Swift heuristics. */
bindingset[name]
private predicate isSensitiveName(string name) {
  name.regexpMatch(any(SensitiveDataType t).getRegexp()) and
  not name.regexpMatch(HeuristicNames::notSensitiveRegexp()) and
  not name.regexpMatch("(?is).*(file|path|url|invalid).*")
}

/**
 * An expression that may contain sensitive data: either a standard `SensitiveExpr`, or a
 * reference to a variable or function whose name indicates that it holds decrypted plaintext.
 */
private class SensitiveOrDecryptedExpr extends Expr {
  string label;

  SensitiveOrDecryptedExpr() {
    label = this.(SensitiveExpr).getLabel()
    or
    not this instanceof SensitiveExpr and
    (
      label = this.(DeclRefExpr).getDecl().(VarDecl).getName()
      or
      label = this.(MemberRefExpr).getMember().(VarDecl).getName()
      or
      label = this.(ApplyExpr).getStaticTarget().(Function).getShortName()
    ) and
    isDecryptedName(label)
  }

  string getLabel() { result = label }
}

/*
 * Pattern 1 (CWE-200): sensitive data copied to the shared pasteboard.
 */

/** Holds if `e` is written to the system pasteboard. */
private predicate isCallArgumentExpr(Expr e, CallExpr call) {
  exists(Location exprLocation, Location argLocation, Argument arg |
    arg = call.getAnArgument() and
    exprLocation = e.getLocation() and
    argLocation = arg.getExpr().getLocation() and
    not exprLocation instanceof UnknownLocation and
    exprLocation.getFile() = argLocation.getFile() and
    exprLocation.getStartLine() >= argLocation.getStartLine() and
    exprLocation.getEndLine() <= argLocation.getEndLine() and
    (
      exprLocation.getStartLine() > argLocation.getStartLine()
      or exprLocation.getStartColumn() >= argLocation.getStartColumn()
    ) and
    (
      exprLocation.getEndLine() < argLocation.getEndLine()
      or exprLocation.getEndColumn() <= argLocation.getEndColumn()
    )
  )
}

private predicate isPasteboardWrite(Expr e, Expr write) {
  exists(AssignExpr assign, FieldDecl f |
    assign.getDest().(MemberRefExpr).getMember() = f and
    f.hasQualifiedName("UIPasteboard",
      ["string", "strings", "url", "urls", "image", "images", "items", "color", "colors"]) and
    e = assign.getSource() and
    write = assign
  )
  or
  exists(CallExpr call |
    call.getStaticTarget()
        .(Method)
        .hasQualifiedName("UIPasteboard",
          [
            "setValue(_:forPasteboardType:)", "setData(_:forPasteboardType:)", "addItems(_:)",
            "setItems(_:options:)", "setObjects(_:)", "setObjects(_:localOnly:expirationDate:)"
          ]) and
    e = call.getArgument(0).getExpr() and
    write = call and
    // Writes that restrict the item to the local device or set an expiration date are safe.
    not exists(Expr opt |
      isCallArgumentExpr(opt, call) and
      (
        opt.(MemberRefExpr).getMember().(VarDecl).getName() = ["localOnly", "expirationDate"] or
        opt.(DeclRefExpr).getDecl().(VarDecl).getName() = ["localOnly", "expirationDate"]
      )
    ) and
    not (
      call.getStaticTarget().(Method)
          .hasQualifiedName("UIPasteboard", "setObjects(_:localOnly:expirationDate:)") and
      (
        not exists(BooleanLiteralExpr localOnly |
          localOnly = call.getArgumentWithLabel("localOnly").getExpr() and localOnly.getValue() = false
        )
        or
        not exists(NilLiteralExpr expirationDate |
          expirationDate = call.getArgumentWithLabel("expirationDate").getExpr()
        )
      )
    )
  )
}

private module PasteboardConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node.asExpr() instanceof SensitiveOrDecryptedExpr }

  predicate isSink(DataFlow::Node node) { isPasteboardWrite(node.asExpr(), _) }

  predicate isBarrier(DataFlow::Node node) {
    node.asExpr() instanceof EncryptedExpr or
    node.asExpr().getType().getUnderlyingType() instanceof BoolType
  }

  predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    // sensitive data stored inside a collection (for example in `addItems`) is still copied.
    isSink(node) and exists(c)
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    // if an object is sensitive, its fields are always sensitive.
    nodeTo.asExpr().(MemberRefExpr).getBase() = nodeFrom.asExpr()
  }
}

private module PasteboardFlow = TaintTracking::Global<PasteboardConfig>;

/*
 * Pattern 2 (CWE-522): a session token derived by reversibly encrypting user credentials.
 */

/** A call to a function that encrypts data (but not one that decrypts it). */
private class EncryptCall extends CallExpr {
  EncryptCall() {
    exists(string name | name = this.getStaticTarget().(Function).getShortName() |
      name.regexpMatch("(?i).*encrypt.*") and
      not name.regexpMatch("(?i).*decrypt.*")
    )
  }
}

/** Holds if `name` looks like the name of a session/authentication token. */
bindingset[name]
private predicate isTokenName(string name) { name.regexpMatch("(?i).*(token|session|cookie).*") }

/** Holds if the result of `call` is stored in a variable or property named like a session token. */
private predicate isTokenProducingCall(EncryptCall call) {
  exists(Expr ref |
    DataFlow::localExprFlow(call, ref) and
    (
      isTokenName(ref.(DeclRefExpr).getDecl().(VarDecl).getName()) or
      isTokenName(ref.(MemberRefExpr).getMember().(VarDecl).getName())
    )
  )
  or
  exists(AssignExpr assign |
    assign.getSource() = call and
    isTokenName(assign.getDest().(MemberRefExpr).getMember().(VarDecl).getName())
  )
  or
  exists(VarDecl v | v.getParentInitializer() = call and isTokenName(v.getName()))
}

private module CredentialTokenConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node.asExpr().(SensitiveExpr).getSensitiveType() instanceof SensitivePassword
  }

  predicate isSink(DataFlow::Node node) {
    exists(EncryptCall call |
      isTokenProducingCall(call) and
      node.asExpr() = call.getAnArgument().getExpr()
    )
  }

  predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    nodeTo.asExpr().(MemberRefExpr).getBase() = nodeFrom.asExpr()
  }
}

private module CredentialTokenFlow = TaintTracking::Global<CredentialTokenConfig>;

/*
 * Pattern 3 (CWE-200): application delegate that does not obscure the window when backgrounded.
 */

/** A class that conforms to `UIApplicationDelegate`. */
private class AppDelegateClass extends ClassDecl {
  AppDelegateClass() { this.getABaseTypeDecl*().getName() = "UIApplicationDelegate" }

  /** Gets a member of this class or of one of its extensions. */
  Decl getAnyMember() {
    result = this.getAMember()
    or
    exists(ExtensionDecl ext | ext.getExtendedTypeDecl() = this and result = ext.getAMember())
  }
}

/** Holds if the application obscures or clears its UI when it moves to the background. */
private predicate obscuresOnBackground(AppDelegateClass delegate) {
  delegate.getAnyMember().(Method).getName() =
    ["applicationDidEnterBackground(_:)", "applicationWillResignActive(_:)"]
}

/** Holds if the program protects its UI on backgrounding outside of the application delegate. */
private predicate obscuresOnBackgroundElsewhere() {
  exists(Method m |
    m.getName() = ["sceneDidEnterBackground(_:)", "sceneWillResignActive(_:)"] and
    exists(m.getBody())
  )
  or
  exists(MemberRefExpr ref |
    not ref.getLocation() instanceof UnknownLocation and
    ref.getMember().(VarDecl).getName() =
      [
        "didEnterBackgroundNotification", "willResignActiveNotification",
        "UIApplicationDidEnterBackground", "UIApplicationWillResignActive"
      ]
  )
}

/** A text input property whose name indicates that the user enters sensitive data into it. */
private class SensitiveInputField extends VarDecl {
  SensitiveInputField() {
    this.getType().getName().regexpMatch(".*\\bUIText(Field|View)\\b.*") and
    exists(string name | name = this.getName() |
      isSensitiveName(name) or
      name.regexpMatch("(?i).*(security|secret).?answer.*")
    )
  }
}

/*
 * Pattern 4 (CWE-922): keychain items without a restrictive accessibility attribute.
 */

/** Holds if `file` references a keychain accessibility attribute. */
private predicate fileSetsKeychainAccessibility(File file) {
  exists(DeclRefExpr ref |
    ref.getDecl().(VarDecl).getName() = ["kSecAttrAccessible", "kSecAttrAccessControl"] and
    ref.getFile() = file
  )
}

/*
 * Pattern 5 (CWE-922): sensitive responses stored in the shared URL cache.
 */

/** Holds if `f` handles sensitive data, so that responses it requests may be sensitive. */
private predicate handlesSensitiveData(Function f) {
  exists(SensitiveExpr e | e.getEnclosingFunction() = f)
  or
  exists(StringLiteralExpr s |
    s.getEnclosingFunction() = f and
    s.getValue()
        .regexpMatch("(?i).*\\b(token|key|password|passwd|secret|session|credentials?|auth)\\b.*")
  )
}

/*
 * Pattern 6 (CWE-316): sensitive data retained in a long-lived class property.
 */

/** A stored property of a class whose name indicates that it holds sensitive data. */
private class SensitiveClassProperty extends VarDecl {
  SensitiveClassProperty() {
    this.getDeclaringDecl() instanceof ClassDecl and
    isSensitiveName(this.getName()) and
    this.getType()
        .getUnderlyingType()
        .getName()
        .regexpMatch("(String|NSString|NSMutableString|Data|NSData|NSMutableData|\\[UInt8\\]|\\[Character\\])[?!]?")
  }
}

/** Holds if `e` clears the value of a property when assigned to it. */
private predicate isClearingValue(Expr e) {
  e instanceof NilLiteralExpr or
  e.(StringLiteralExpr).getValue() = "" or
  e.(ArrayExpr).getNumberOfElements() = 0 or
  (
    e.(CallExpr).getStaticTarget() instanceof Initializer and
    e.(CallExpr).getNumberOfArguments() = 0
  )
}

/** Holds if `v` is cleared somewhere in the program. */
private predicate isCleared(SensitiveClassProperty v) {
  exists(AssignExpr assign |
    assign.getDest().(MemberRefExpr).getMember() = v and
    isClearingValue(assign.getSource().getFullyUnresolved())
  )
  or
  exists(MethodCallExpr call |
    call.getQualifier().(MemberRefExpr).getMember() = v and
    call.getStaticTarget().getShortName() = ["removeAll", "resetBytes"]
  )
}

from AstNode alert, string message, AstNode related, string relatedLabel
where
  (
    // Pattern 1: pasteboard.
    exists(DataFlow::Node source, DataFlow::Node sink |
      PasteboardFlow::flow(source, sink) and
      isPasteboardWrite(sink.asExpr(), alert) and
      message =
        "Sensitive data from $@ is copied to the shared pasteboard without an expiration date or local-only restriction." and
      related = source.asExpr() and
      relatedLabel = source.asExpr().(SensitiveOrDecryptedExpr).getLabel()
    )
    or
    // Pattern 2: credential-derived session token.
    exists(DataFlow::Node source, DataFlow::Node sink, EncryptCall call |
      CredentialTokenFlow::flow(source, sink) and
      sink.asExpr() = call.getAnArgument().getExpr() and
      alert = call and
      message =
        "This session token is derived by reversibly encrypting $@; use a random, server-issued token instead." and
      related = source.asExpr() and
      relatedLabel = source.asExpr().(SensitiveExpr).getLabel()
    )
    or
    // Pattern 3: no background snapshot protection.
    exists(AppDelegateClass delegate, SensitiveInputField field |
      not obscuresOnBackground(delegate) and
      not obscuresOnBackgroundElsewhere() and
      field =
        min(SensitiveInputField f |
          |
          f
          order by
            f.getLocation().getFile().getAbsolutePath(), f.getLocation().getStartLine(),
            f.getLocation().getStartColumn()
        ) and
      alert = delegate and
      message =
        "This application delegate does not obscure the window when the app enters the background, so the system snapshot may capture sensitive input such as $@." and
      related = field and
      relatedLabel = field.getName()
    )
    or
    // Pattern 4a: keychain item added without an explicit accessibility attribute.
    exists(CallExpr call |
      call.getStaticTarget().(Function).getName() = "SecItemAdd(_:_:)" and
      not fileSetsKeychainAccessibility(call.getFile()) and
      alert = call and
      message =
        "This keychain item is added using $@ without a restrictive kSecAttrAccessible value, so the default accessibility applies." and
      related = call.getArgument(0).getExpr() and
      relatedLabel = "this attribute dictionary"
    )
    or
    // Pattern 4b: keychain item that is always accessible.
    exists(DeclRefExpr ref, string name |
      name = ref.getDecl().(VarDecl).getName() and
      name = ["kSecAttrAccessibleAlways", "kSecAttrAccessibleAlwaysThisDeviceOnly"] and
      alert = ref and
      message =
        "This keychain item uses the accessibility class $@, which leaves it readable while the device is locked." and
      related = ref and
      relatedLabel = name
    )
    or
    // Pattern 5: sensitive response cached.
    exists(EnumElementExpr e, Function f |
      e.getElement().getName() = ["returnCacheDataElseLoad", "returnCacheDataDontLoad"] and
      f = e.getEnclosingFunction() and
      handlesSensitiveData(f) and
      alert = e and
      message =
        "This request uses a cache policy that serves stored responses, so sensitive data handled in $@ may be persisted in the shared URL cache." and
      related = f and
      relatedLabel = f.getName()
    )
    or
    // Pattern 6: sensitive value retained in memory.
    exists(AssignExpr assign, SensitiveClassProperty v |
      assign.getDest().(MemberRefExpr).getMember() = v and
      not isClearingValue(assign.getSource().getFullyUnresolved()) and
      not isCleared(v) and
      alert = assign and
      message =
        "Sensitive data is stored in the long-lived property $@, which is never cleared after use." and
      related = v and
      relatedLabel = v.getName()
    )
  ) and
  // ignore compiler-synthesized code, such as implicit property accessors.
  not alert.getLocation() instanceof UnknownLocation
select alert, message, related, relatedLabel
