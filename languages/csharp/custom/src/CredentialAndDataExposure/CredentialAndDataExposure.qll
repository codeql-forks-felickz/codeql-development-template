/**
 * Provides detectors for credential and sensitive-data exposure in C# code that are not
 * covered by the standard `cs/cleartext-storage-of-sensitive-information`,
 * `cs/exposure-of-sensitive-information`, `cs/hardcoded-credentials` and
 * `cs/hard-coded-symmetric-encryption-key` queries.
 */

import csharp
private import semmle.code.csharp.security.SensitiveActions
private import semmle.code.csharp.security.dataflow.flowsinks.ExternalLocationSink
private import semmle.code.csharp.security.dataflow.flowsources.Remote
private import semmle.code.csharp.security.dataflow.flowsources.Stored
private import semmle.code.csharp.frameworks.Sql
private import semmle.code.csharp.dataflow.internal.ExternalFlow as ExternalFlow

/* ------------------------------------------------------------------------- */
/* Shared heuristics                                                          */
/* ------------------------------------------------------------------------- */
/** Holds if `name` looks like the name of something holding a password. */
bindingset[name]
predicate isCredentialName(string name) {
  name.regexpMatch("(?i).*(passw(or)?d?|passwort|passphrase|pwd)") and
  not name.regexpMatch("(?i).*(hash|crypt|salt|invalid|hint|confirm|policy|reset).*")
}

/** Holds if `name` looks like the name of a payment-card number. */
bindingset[name]
private predicate isCardNumberName(string name) {
  name.regexpMatch("(?i).*(credit_?card(_?(number|num|no))?|card_?(number|num|no)|cc_?(number|num|no)|ccnum)") and
  not name.regexpMatch("(?i).*(mask|last|hash|crypt|token|type|brand|valid|remember|holder|expir).*")
}

/** Holds if `t` is a type that may hold a textual secret. */
private predicate isSecretType(Type t) {
  t instanceof StringType
  or
  t.(ArrayType).getElementType() instanceof CharType
  or
  t.(ArrayType).getElementType() instanceof ByteType
}

/** Holds if `m` looks like it protects (hashes, encrypts, masks, ...) its input. */
private predicate isProtectingCallable(Callable m) {
  m.getName()
      .regexpMatch("(?i).*(hash|crypt|protect|digest|derive|pbkdf|scrypt|argon|hmac|mask|tokeni[sz]e|redact).*")
}

/** Holds if `t` is a type that hashes or derives keys from its input. */
private predicate isProtectingType(Type t) {
  t.getName()
      .regexpMatch("(?i).*(hash|hmac|sha[0-9]*|md5|derive|pbkdf|bcrypt|scrypt|argon|crypt).*")
}

/** A node that protects sensitive data, so that taint is not propagated through it. */
private predicate isProtectionBarrier(DataFlow::Node n) {
  isProtectingCallable(n.asExpr().(Call).getTarget())
  or
  isProtectingType(n.asExpr().(ObjectCreation).getObjectType())
}

/** A property that holds a password. */
class CredentialProperty extends Property {
  CredentialProperty() { isCredentialName(this.getName()) and isSecretType(this.getType()) }
}

/** A property that holds a full payment-card number. */
private class CardNumberProperty extends Property {
  CardNumberProperty() {
    (
      this.getType() instanceof StringType or
      this.getType() instanceof LongType or
      this.getType() instanceof DecimalType
    ) and
    (
      isCardNumberName(this.getName())
      or
      this.getName() = "Number" and
      this.getDeclaringType().getName().regexpMatch("(?i).*card.*")
    )
  }
}

/** An expression that likely evaluates to a password. */
class CredentialExpr extends Expr {
  CredentialExpr() {
    isSecretType(this.getType()) and
    (
      this instanceof PasswordExpr and not isProtectingCallable(this.(Call).getTarget())
      or
      isCredentialName(this.(AssignableRead).getTarget().getName())
      or
      exists(Call c, Expr arg |
        c = this and
        not isProtectingCallable(c.getTarget()) and
        arg = c.getAnArgument()
      |
        isCredentialName(c.getTarget().getName())
        or
        isCredentialName(arg.getValue())
        or
        isCredentialName(arg.(FieldAccess).getTarget().getName())
      )
      or
      isCredentialName(this.(ElementAccess).getAnIndex().getValue())
    )
  }
}

/** An expression that likely evaluates to a full payment-card number. */
class CardNumberExpr extends Expr {
  CardNumberExpr() {
    (
      this.getType() instanceof StringType or
      this.getType() instanceof LongType or
      this.getType() instanceof DecimalType
    ) and
    exists(Assignable a | a = this.(AssignableRead).getTarget() |
      isCardNumberName(a.getName())
      or
      a.getName() = "Number" and
      a.(Member).getDeclaringType().getName().regexpMatch("(?i).*card.*")
    )
  }
}

/** Holds if `c` is an Entity Framework `DbContext` subclass with a `DbSet<entity>` property. */
private predicate isEfEntity(Class entity) {
  exists(Class ctx, Property dbset, ConstructedType setType |
    ctx.getABaseType+()
        .hasFullyQualifiedName(["Microsoft.EntityFrameworkCore", "System.Data.Entity"], "DbContext") and
    dbset = ctx.getAProperty() and
    setType = dbset.getType() and
    setType
        .getUnboundGeneric()
        .hasFullyQualifiedName(["Microsoft.EntityFrameworkCore", "System.Data.Entity"], "DbSet`1") and
    setType.getTypeArgument(0) = entity
  )
}

/** Holds if `sink` renders a full payment-card number property into a Razor view. */
private predicate razorCardNumberRender(Expr sink, CardNumberProperty p) {
  exists(MethodCall write |
    write.getTarget().hasName("Write") and
    write
        .getTarget()
        .getDeclaringType()
        .getABaseType*()
        .hasFullyQualifiedName(["Microsoft.AspNetCore.Mvc.Razor", "System.Web.WebPages"],
          ["RazorPageBase", "WebPageExecutingBase"]) and
    sink = write and
    p = write.getArgument(0).(PropertyAccess).getTarget().getUnboundDeclaration()
  )
  or
  exists(MethodCall mc, LambdaExpr l, string name |
    name = mc.getTarget().getUndecoratedName() and
    name =
      [
        "DisplayFor", "DisplayTextFor", "EditorFor", "TextBoxFor", "TextAreaFor", "HiddenFor",
        "ValueFor"
      ] and
    mc.getTarget()
        .getDeclaringType()
        .getNamespace()
        .hasFullyQualifiedName(["Microsoft.AspNetCore.Mvc", "System.Web.Mvc"], ["Rendering", "Html"]) and
    l = mc.getAnArgument() and
    p = l.getExpressionBody().(PropertyAccess).getTarget().getUnboundDeclaration() and
    sink = mc
  )
  or
  exists(ExprStmt s, string helper |
    tagHelperForAssignment(s, helper, _) and
    helper = "InputTagHelper" and
    exists(AssignExpr a, PropertyAccess pa, LambdaExpr l |
      a = s.getExpr() and
      pa = a.getLeftOperand() and
      l = a.getRightOperand().(Call).getAnArgument() and
      p = l.getExpressionBody().(PropertyAccess).getTarget().getUnboundDeclaration()
    ) and
    sink = s.getExpr()
  )
}

/** Holds if `e` is the value written to property `p`. */
private predicate propertyWrite(Expr e, Property p) {
  exists(AssignExpr a |
    a.getLeftOperand().(PropertyAccess).getTarget().getUnboundDeclaration() = p and
    e = a.getRightOperand()
  )
}

/* ------------------------------------------------------------------------- */
/* CWE-523: credentials submitted by an HTML form over plain HTTP             */
/* ------------------------------------------------------------------------- */
/** A string literal opening an HTML form whose `action` is an `http://` URL. */
private class HttpFormLiteral extends StringLiteral {
  HttpFormLiteral() {
    this.getValue().regexpMatch("(?is).*<form\\b[^>]*\\baction\\s*=\\s*['\"]?http://.*")
  }
}

/** A string literal containing an HTML password input. */
private class PasswordInputLiteral extends StringLiteral {
  PasswordInputLiteral() {
    this.getValue().regexpMatch("(?is).*<input\\b[^>]*\\btype\\s*=\\s*['\"]?password\\b.*")
  }
}

/** A string literal opening a form that submits fields through the URL. */
private class GetFormLiteral extends StringLiteral {
  GetFormLiteral() {
    this.getValue().regexpMatch("(?is).*<form\\b[^>]*\\bmethod\\s*=\\s*['\"]?get\\b.*")
  }
}

/** Holds if `form` is an HTML login form that posts credentials over unencrypted HTTP. */
predicate credentialFormOverHttp(HttpFormLiteral form) {
  exists(PasswordInputLiteral pw | pw.getEnclosingCallable() = form.getEnclosingCallable())
}

/** Holds if `form` submits a password field using the GET method. */
private predicate credentialFormOverGet(GetFormLiteral form) {
  exists(PasswordInputLiteral pw | pw.getEnclosingCallable() = form.getEnclosingCallable())
}

/* ------------------------------------------------------------------------- */
/* CWE-200: stored credentials rendered into a web response                  */
/* ------------------------------------------------------------------------- */
/** Holds if `p` is annotated as a password, so tag helpers / editors render it masked. */
private predicate isDataTypePassword(Property p) {
  exists(Attribute a | a = p.getAnAttribute() |
    a.getType().hasName("DataTypeAttribute") and
    a.getArgument(_).(MemberConstantAccess).getTarget().hasName("Password")
    or
    a.getType().hasName("PasswordPropertyTextAttribute")
  )
}

/** Gets a credential property read by the body of lambda `l`. */
private CredentialProperty lambdaCredentialProperty(LambdaExpr l) {
  result = l.getExpressionBody().(PropertyAccess).getTarget().getUnboundDeclaration()
}

/** Holds if `e` is the value assigned to the `For` property of an input or text area tag helper. */
private predicate tagHelperForAssignment(ExprStmt s, string helper, Expr instance) {
  exists(AssignExpr a, PropertyAccess pa |
    a = s.getExpr() and
    pa = a.getLeftOperand() and
    pa.getTarget().hasName("For") and
    pa.getTarget()
        .getDeclaringType()
        .hasFullyQualifiedName("Microsoft.AspNetCore.Mvc.TagHelpers", helper) and
    helper = ["InputTagHelper", "TextAreaTagHelper"] and
    sameTagHelperInstance(instance, pa.getQualifier())
  )
}

/** Holds if `s` assigns a credential property to the `For` property of a tag helper. */
private predicate tagHelperCredentialForAssignment(ExprStmt s, string helper, CredentialProperty p) {
  exists(AssignExpr a, PropertyAccess pa, LambdaExpr l |
    a = s.getExpr() and
    pa = a.getLeftOperand() and
    tagHelperForAssignment(s, helper, pa.getQualifier()) and
    l = a.getRightOperand().(Call).getAnArgument() and
    p = lambdaCredentialProperty(l)
  )
}

/** Holds if `e1` and `e2` refer to the same tag helper field or local. */
private predicate sameTagHelperInstance(Expr e1, Expr e2) {
  e1 = e2
  or
  exists(AssignableRead r1, AssignableRead r2 |
    e1 = r1 and
    e2 = r2 and
    r1.getTarget() = r2.getTarget()
  )
}

/** Holds if `s` allocates a new tag helper into `instance`. */
private predicate tagHelperAllocation(ExprStmt s, string helper, Expr instance) {
  exists(AssignExpr a, ObjectCreation oc |
    a = s.getExpr() and
    oc = a.getRightOperand() and
    oc.getObjectType().hasFullyQualifiedName("Microsoft.AspNetCore.Mvc.TagHelpers", helper) and
    helper = ["InputTagHelper", "TextAreaTagHelper"] and
    sameTagHelperInstance(instance, a.getLeftOperand())
  )
}

/** Holds if `e` is a value equal to `"password"`, possibly via a generated `TagHelperAttribute` field. */
private predicate isPasswordTypeValue(Expr e) {
  e.getValue().toLowerCase() = "password"
  or
  isPasswordTypeValue(e.(CastExpr).getExpr())
  or
  exists(PropertyAccess v, Field f |
    v = e and
    v.getTarget().hasName("Value") and
    f = v.getQualifier().(FieldAccess).getTarget() and
    f.getInitializer().(ObjectCreation).getArgument(1).getValue().toLowerCase() = "password"
  )
}

/** Holds if `typeStmt` assigns an input type to the specified helper instance. */
private predicate tagHelperInputTypeAssignment(ExprStmt typeStmt, Expr instance, Expr value) {
  exists(AssignExpr a, PropertyAccess pa |
    a = typeStmt.getExpr() and
    pa = a.getLeftOperand() and
    pa.getTarget().hasName("InputTypeName") and
    pa.getTarget()
        .getDeclaringType()
        .hasFullyQualifiedName("Microsoft.AspNetCore.Mvc.TagHelpers", "InputTagHelper") and
    sameTagHelperInstance(instance, pa.getQualifier()) and
    value = a.getRightOperand()
  )
}

/** Holds if `s` has an explicit input type, and identifies the value assigned. */
private predicate inputTypeAssignmentForElement(ExprStmt s, Expr value) {
  exists(BlockStmt b, int i, int j, ExprStmt typeStmt, string helper, Expr instance |
    tagHelperForAssignment(s, helper, instance) and
    helper = "InputTagHelper" and
    b.getStmt(i) = s and
    b.getStmt(j) = typeStmt and
    j > i and
    tagHelperInputTypeAssignment(typeStmt, instance, value) and
    not exists(int k, ExprStmt other |
      k in [i + 1 .. j - 1] and
      b.getStmt(k) = other and
      (
        tagHelperForAssignment(other, helper, instance) or
        tagHelperAllocation(other, helper, instance)
      )
    )
  )
}

/** Holds if `s` explicitly sets the input type to `password`. */
private predicate isPasswordInputElement(ExprStmt s) {
  exists(Expr type |
    inputTypeAssignmentForElement(s, type) and
    isPasswordTypeValue(type)
  )
}

/** Holds if the tag helper element whose `For` assignment is `s` has an explicit input type. */
private predicate hasExplicitInputType(ExprStmt s) {
  exists(Expr type | inputTypeAssignmentForElement(s, type))
}

/** Holds if `sink` renders the credential property `p` into a Razor view. */
private predicate razorCredentialRender(Expr sink, CredentialProperty p) {
  // `@Model.Password`
  exists(MethodCall write |
    write.getTarget().hasName("Write") and
    write
        .getTarget()
        .getDeclaringType()
        .getABaseType*()
        .hasFullyQualifiedName(["Microsoft.AspNetCore.Mvc.Razor", "System.Web.WebPages"],
          ["RazorPageBase", "WebPageExecutingBase"]) and
    sink = write and
    p = write.getArgument(0).(PropertyAccess).getTarget().getUnboundDeclaration()
  )
  or
  // `@Html.DisplayFor(m => m.Password)` and similar helpers that render the value
  exists(MethodCall mc, LambdaExpr l, string name |
    name = mc.getTarget().getUndecoratedName() and
    name =
      [
        "DisplayFor", "DisplayTextFor", "EditorFor", "TextBoxFor", "TextAreaFor", "HiddenFor",
        "ValueFor"
      ] and
    mc.getTarget()
        .getDeclaringType()
        .getNamespace()
        .hasFullyQualifiedName(["Microsoft.AspNetCore.Mvc", "System.Web.Mvc"], ["Rendering", "Html"]) and
    l = mc.getAnArgument() and
    p = lambdaCredentialProperty(l) and
    sink = mc and
    not (name = "EditorFor" and isDataTypePassword(p))
  )
  or
  // `<input asp-for="Password" />`
  exists(ExprStmt s, string helper |
    tagHelperCredentialForAssignment(s, helper, p) and
    sink = s.getExpr() and
    not (
      helper = "InputTagHelper" and
      (
        isPasswordInputElement(s)
        or
        not hasExplicitInputType(s) and isDataTypePassword(p)
      )
    )
  )
}

/** Holds if `pa` writes the rendered value of a Web Forms control. */
private predicate webFormsControlTextWrite(Expr rhs, PropertyAccess pa) {
  exists(AssignExpr a |
    a.getLeftOperand() = pa and
    rhs = a.getRightOperand() and
    pa.getTarget().getName() = ["Text", "Value"] and
    pa.getTarget()
        .getDeclaringType()
        .getABaseType*()
        .getNamespace()
        .hasFullyQualifiedName("System.Web.UI", ["WebControls", "HtmlControls"])
  )
}

/** Holds if the control accessed by `pa` is put into password mode, so its text is never rendered. */
private predicate isPasswordModeControl(PropertyAccess pa) {
  exists(Field f, AssignExpr mode, PropertyAccess modeAccess |
    f = pa.getQualifier().(FieldAccess).getTarget() and
    modeAccess = mode.getLeftOperand() and
    modeAccess.getTarget().hasName("TextMode") and
    modeAccess.getQualifier().(FieldAccess).getTarget() = f and
    mode.getRightOperand().(MemberConstantAccess).getTarget().hasName("Password")
  )
}

private module CredentialToWebControlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof CredentialExpr }

  predicate isSink(DataFlow::Node sink) {
    exists(PropertyAccess pa |
      webFormsControlTextWrite(sink.asExpr(), pa) and
      not isPasswordModeControl(pa)
    )
  }

  predicate isBarrier(DataFlow::Node node) { isProtectionBarrier(node) }
}

private module CredentialToWebControlFlow = TaintTracking::Global<CredentialToWebControlConfig>;

/* ------------------------------------------------------------------------- */
/* CWE-256: model-bound password persisted verbatim through Entity Framework */
/* ------------------------------------------------------------------------- */
/** Holds if `arg` is passed to an Entity Framework method that persists an entity. */
private predicate efPersistArgument(Expr arg) {
  exists(MethodCall mc, Method m |
    m = mc.getTarget().getUnboundDeclaration() and
    m.getUndecoratedName() =
      ["Add", "AddAsync", "Update", "Attach", "AddRange", "UpdateRange", "AttachRange"] and
    m.getDeclaringType()
        .getABaseType*()
        .getUnboundDeclaration()
        .hasFullyQualifiedName(["Microsoft.EntityFrameworkCore", "System.Data.Entity"],
          ["DbContext", "DbSet`1"]) and
    arg = mc.getAnArgument()
  )
}

/** Gets a credential property of the model type of the remote source `n`. */
private CredentialProperty boundCredentialProperty(DataFlow::ParameterNode n) {
  n instanceof RemoteFlowSource and
  result = n.getParameter().getType().(RefType).getAProperty()
}

private module BoundPasswordToEfConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { exists(boundCredentialProperty(source)) }

  predicate isSink(DataFlow::Node sink) { efPersistArgument(sink.asExpr()) }
}

private module BoundPasswordToEfFlow = DataFlow::Global<BoundPasswordToEfConfig>;

/* ------------------------------------------------------------------------- */
/* CWE-256 / CWE-315: password "protected" only by a reversible encoding     */
/* ------------------------------------------------------------------------- */
/** Holds if `pred` is encoded (for example Base64) by a reversible transformation into `succ`. */
private predicate reversibleEncodingStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(Call c | c = succ.asExpr() |
    (
      c.getTarget().getDeclaringType().hasFullyQualifiedName("System", "Convert") and
      c.getTarget()
          .hasName(["ToBase64String", "ToBase64CharArray", "ToHexString", "ToHexStringLower"])
      or
      c.getTarget() instanceof Method and
      c.getTarget().getName().regexpMatch("(?i).*(base64|encode).*") and
      not c.getTarget().getName().regexpMatch("(?i).*(url|html|xml|javascript|uri|ldap).*")
      or
      c instanceof ObjectCreation and
      c.(ObjectCreation).getObjectType().getName().regexpMatch("(?i).*(base64|encoder).*")
    ) and
    not isProtectingCallable(c.getTarget()) and
    (
      pred.asExpr() = c.getAnArgument()
      or
      pred.asExpr() = c.(MethodCall).getQualifier()
    )
  )
}

/** Holds if `sql` is (tainted by) an `INSERT`, `UPDATE` or `MERGE` statement. */
private predicate isSqlWrite(Expr sql) {
  exists(StringLiteral lit |
    lit.getValue().regexpMatch("(?is)\\s*(insert|update|merge)\\b.*") and
    TaintTracking::localExprTaint(lit, sql)
  )
}

/** A location where a credential is stored or persisted outside of the application. */
private predicate credentialStoreSink(DataFlow::Node sink) {
  sink instanceof ExternalLocationSink
  or
  exists(Expr sql | sql = sink.asExpr() and isSqlWrite(sql) |
    sql = any(SqlExpr e).getSql() or ExternalFlow::sinkNode(sink, "sql-injection")
  )
  or
  exists(CredentialProperty p | isEfEntity(p.getDeclaringType()) | propertyWrite(sink.asExpr(), p))
}

private newtype TEncodingState =
  TPlain() or
  TEncoded()

private module ReversibleEncodingConfig implements DataFlow::StateConfigSig {
  class FlowState = TEncodingState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    source.asExpr() instanceof CredentialExpr and state = TPlain()
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    credentialStoreSink(sink) and state = TEncoded()
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    reversibleEncodingStep(node1, node2) and exists(state1) and state2 = TEncoded()
  }

  predicate isBarrier(DataFlow::Node node) { isProtectionBarrier(node) }
}

private module ReversibleEncodingFlow = TaintTracking::GlobalWithState<ReversibleEncodingConfig>;

/* ------------------------------------------------------------------------- */
/* CWE-256: plaintext password bound to an INSERT / UPDATE statement         */
/* ------------------------------------------------------------------------- */
/** Holds if `e` is the value bound to a password parameter of an `INSERT` or `UPDATE` command. */
private predicate sqlPasswordParameterValue(Expr e) {
  exists(MethodCall c, Expr name, Expr collection |
    collection = c.getQualifier() and
    isSqlParameterCollection(collection) and
    (
      c.getTarget().hasName("AddWithValue") and
      name = c.getArgument(0) and
      e = c.getArgument(1)
      or
      c.getTarget().hasName("Add") and
      exists(ObjectCreation parameter |
        parameter = c.getArgument(0) and
        parameter
            .getObjectType()
            .getABaseType*()
            .hasFullyQualifiedName(["System.Data", "System.Data.Common"],
              ["IDataParameter", "DbParameter"]) and
        parameter.getNumberOfArguments() = 2 and
        name = parameter.getArgument(0) and
        e = parameter.getArgument(1)
      ) and
      not e.getType() instanceof Enum
    ) and
    isCredentialName(name.getValue().regexpReplaceAll("^[@:?$]", "")) and
    exists(Expr sql |
      isSqlWrite(sql) and
      sqlCommandForParameterCollection(collection, sql)
    )
  )
}

/** Holds if `e` is a recognized SQL parameter collection. */
private predicate isSqlParameterCollection(Expr e) {
  e.getType()
      .(RefType)
      .getABaseType*()
      .hasFullyQualifiedName([
          "System.Data.Common", "System.Data.SqlClient", "Microsoft.Data.SqlClient"
        ], ["DbParameterCollection", "SqlParameterCollection"])
}

/** Gets the command that owns a SQL parameter collection. */
private predicate sqlParameterCollectionCommand(Expr collection, Expr command) {
  exists(PropertyAccess parameters |
    parameters = collection and
    parameters.getTarget().hasName("Parameters") and
    command = parameters.getQualifier()
  )
}

/** Holds if `sql` is the text of the command owning `collection`. */
private predicate sqlCommandForParameterCollection(Expr collection, Expr sql) {
  exists(Expr command |
    sqlParameterCollectionCommand(collection, command) and
    (
      exists(SqlExpr commandCreation |
        commandCreation instanceof ObjectCreation and
        sql = commandCreation.getSql() and
        DataFlow::localExprFlow(commandCreation, command)
      )
      or
      exists(ObjectCreation commandCreation |
        commandCreation
            .getObjectType()
            .getABaseType*()
            .hasFullyQualifiedName(["System.Data.SqlClient", "Microsoft.Data.SqlClient"],
              "SqlCommand") and
        sql = commandCreation.getArgument(0) and
        DataFlow::localExprFlow(commandCreation, command)
      )
      or
      exists(CommandTextAssignmentSqlExpr commandText |
        sql = commandText.getSql() and
        DataFlow::localExprFlow(commandText.getLeftOperand().(PropertyAccess).getQualifier(),
          command)
      )
    )
  )
}

private module PlaintextPasswordSqlParameterConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof CredentialExpr
    or
    source.asExpr().(StringLiteral).getValue() != ""
  }

  predicate isSink(DataFlow::Node sink) { sqlPasswordParameterValue(sink.asExpr()) }

  predicate isBarrier(DataFlow::Node node) {
    isProtectionBarrier(node) or reversibleEncodingStep(_, node)
  }
}

private module PlaintextPasswordSqlParameterFlow =
  TaintTracking::Global<PlaintextPasswordSqlParameterConfig>;

/* ------------------------------------------------------------------------- */
/* CWE-256: password read from a plaintext file used as a credential          */
/* ------------------------------------------------------------------------- */
/** Holds if `e` is used as the password of a database or network connection. */
private predicate connectionPasswordValue(Expr e) {
  // a value appended right after a `Password` / `Pwd` key in a connection string literal
  exists(AddExpr add, Expr left |
    e = add.getRightOperand() and
    left = [add.getLeftOperand(), add.getLeftOperand().(AddExpr).getRightOperand()] and
    left.getValue().regexpMatch("(?is).*\\b(password|pwd)\\s*=\\s*")
  )
  or
  // the same, inside an interpolated string
  exists(InterpolatedStringExpr ise, int i |
    e = ise.getChild(i) and
    ise.getChild(i - 1).(Expr).getValue().regexpMatch("(?is).*\\b(password|pwd)\\s*=\\s*")
  )
  or
  exists(Property p |
    propertyWrite(e, p) and
    p.hasName("Password") and
    p.getDeclaringType()
        .getABaseType*()
        .hasFullyQualifiedName(["System.Data.Common", "System.Net"],
          ["DbConnectionStringBuilder", "NetworkCredential"])
  )
  or
  exists(ObjectCreation oc |
    oc.getObjectType().hasFullyQualifiedName("System.Net", "NetworkCredential") and
    e = oc.getArgument(1)
  )
}

private module PlaintextCredentialFileConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FileStreamStoredFlowSource }

  predicate isSink(DataFlow::Node sink) { connectionPasswordValue(sink.asExpr()) }

  predicate isBarrier(DataFlow::Node node) { isProtectionBarrier(node) }
}

private module PlaintextCredentialFileFlow = TaintTracking::Global<PlaintextCredentialFileConfig>;

/* ------------------------------------------------------------------------- */
/* CWE-257: stored password decoded or decrypted back to plaintext           */
/* ------------------------------------------------------------------------- */
/** A read of a password column from a data row or data reader. */
private class StoredPasswordRead extends ElementAccess {
  StoredPasswordRead() {
    isCredentialName(this.getAnIndex().getValue()) and
    this.getQualifier()
        .getType()
        .(RefType)
        .getABaseType*()
        .hasFullyQualifiedName("System.Data", ["DataRow", "DataRowView", "IDataRecord"])
  }
}

/** Holds if `e` is the input of a call that reverses an encoding or encryption. */
private predicate decodedValue(Expr e) {
  exists(Call c |
    (
      (e = c.getAnArgument() or e = c.(MethodCall).getQualifier()) and
      c.getTarget().getDeclaringType().hasFullyQualifiedName("System", "Convert") and
      c.getTarget().hasName(["FromBase64String", "FromBase64CharArray", "FromHexString"])
      or
      (e = c.getAnArgument() or e = c.(MethodCall).getQualifier()) and
      c.getTarget().getName().regexpMatch("(?i).*(decode|decrypt|unprotect).*") and
      not c.getTarget().getName().regexpMatch("(?i).*(url|html|xml|javascript|uri|ldap).*")
    ) and
    isDecodedPlaintextResult(c)
  )
}

/** Holds if `decoded` is converted back to plaintext after decoding. */
private predicate isDecodedPlaintextResult(Call decoded) {
  exists(MethodCall getString |
    getString.getTarget().hasName("GetString") and
    getString.getTarget().getDeclaringType().hasFullyQualifiedName("System.Text", "Encoding") and
    DataFlow::localExprFlow(decoded, getString.getArgument(0))
  )
  or
  exists(ObjectCreation stringCreation |
    stringCreation.getObjectType().hasFullyQualifiedName("System", "String") and
    DataFlow::localExprFlow(decoded, stringCreation.getAnArgument())
  )
  or
  decoded.getTarget().getName().regexpMatch("(?i).*(decode|decrypt|unprotect).*") and
  not decoded.getTarget().getName().regexpMatch("(?i).*(url|html|xml|javascript|uri|ldap).*")
}

private module StoredPasswordRecoveryConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof StoredPasswordRead }

  predicate isSink(DataFlow::Node sink) {
    decodedValue(sink.asExpr()) and
    // report the call site rather than the implementation of a decoding helper
    not sink.getEnclosingCallable().getName().regexpMatch("(?i).*(decode|decrypt|unprotect).*")
  }
}

private module StoredPasswordRecoveryFlow = TaintTracking::Global<StoredPasswordRecoveryConfig>;

/* ------------------------------------------------------------------------- */
/* CWE-257: password stored using reversible (symmetric) encryption          */
/* ------------------------------------------------------------------------- */
/** Holds if `e` is (locally) the result of creating a symmetric encryptor. */
private predicate isEncryptor(Expr e) {
  exists(MethodCall create |
    create.getTarget().hasName("CreateEncryptor") and
    create
        .getTarget()
        .getDeclaringType()
        .getNamespace()
        .hasFullyQualifiedName("System.Security", "Cryptography") and
    DataFlow::localExprFlow(create, e)
  )
}

/** Holds if `e` is (locally) a `CryptoStream` that encrypts data written to it. */
private predicate isEncryptingStream(Expr e) {
  exists(ObjectCreation cs |
    cs.getObjectType().hasFullyQualifiedName("System.Security.Cryptography", "CryptoStream") and
    isEncryptor(cs.getArgument(1)) and
    cs.getArgument(2).(MemberConstantAccess).getTarget().hasName("Write") and
    DataFlow::localExprFlow(cs, e)
  )
}

/** Holds if `e` is plaintext that is symmetrically encrypted. */
private predicate encryptionPlaintext(Expr e) {
  exists(MethodCall mc, Method m | m = mc.getTarget() |
    // writes to a CryptoStream, directly or through a StreamWriter
    m.getName().matches("Write%") and
    e = mc.getArgument(0) and
    (
      isEncryptingStream(mc.getQualifier())
      or
      exists(ObjectCreation writer |
        writer.getObjectType().hasFullyQualifiedName("System.IO", "StreamWriter") and
        isEncryptingStream(writer.getArgument(0)) and
        DataFlow::localExprFlow(writer, mc.getQualifier())
      )
    )
    or
    // ICryptoTransform.TransformFinalBlock / TransformBlock on an encryptor
    m.getName() = ["TransformFinalBlock", "TransformBlock"] and
    isEncryptor(mc.getQualifier()) and
    e = mc.getArgument(0)
    or
    // SymmetricAlgorithm.EncryptCbc / EncryptEcb / EncryptCfb
    m.getName() = ["EncryptCbc", "EncryptEcb", "EncryptCfb"] and
    m.getDeclaringType()
        .getABaseType*()
        .hasFullyQualifiedName("System.Security.Cryptography", "SymmetricAlgorithm") and
    e = mc.getArgument(0)
  )
}

private module PasswordEncryptionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof CredentialExpr }

  predicate isSink(DataFlow::Node sink) { encryptionPlaintext(sink.asExpr()) }

  predicate isBarrier(DataFlow::Node node) {
    isProtectionBarrier(node) and not encryptionPlaintext(node.asExpr())
  }
}

private module PasswordEncryptionFlow = TaintTracking::Global<PasswordEncryptionConfig>;

/* ------------------------------------------------------------------------- */
/* CWE-532: object whose ToString() includes a password written to a log     */
/* ------------------------------------------------------------------------- */
/** A `ToString()` override that includes a credential member of its own object. */
private class CredentialToString extends Method {
  CredentialToString() {
    this.hasName("ToString") and
    this.getNumberOfParameters() = 0 and
    this.fromSource() and
    exists(PropertyAccess pa, ReturnStmt ret |
      pa.getEnclosingCallable() = this and
      pa.getTarget() instanceof CredentialProperty and
      (not exists(pa.getQualifier()) or pa.getQualifier() instanceof ThisAccess) and
      ret.getEnclosingCallable() = this and
      localTaintWithoutProtectors(DataFlow::exprNode(pa), DataFlow::exprNode(ret.getExpr()))
    )
  }
}

/** Holds if local taint flows from `source` to `sink` without passing through a protecting call. */
private predicate localTaintStepWithoutProtectors(DataFlow::Node source, DataFlow::Node sink) {
  TaintTracking::localTaintStep(source, sink) and
  not exists(Call c |
    c = sink.asExpr() and
    isProtectingCallable(c.getTarget())
  )
}

/** Holds if local taint flows from `source` to `sink` without passing through a protecting call. */
private predicate localTaintWithoutProtectors(DataFlow::Node source, DataFlow::Node sink) {
  source = sink or
  localTaintStepWithoutProtectors*(source, sink)
}

/** Holds if `t` has a `ToString()` method that includes a credential. */
private predicate hasCredentialToString(ValueOrRefType t) {
  t.getAMember() instanceof CredentialToString
  or
  hasCredentialToString(t.getBaseClass())
}

/** An expression whose string representation includes a credential. */
private class CredentialStringConversion extends Expr {
  CredentialStringConversion() {
    this.(MethodCall).getTarget() instanceof CredentialToString
    or
    hasCredentialToString(this.getType()) and
    (
      this = any(InterpolatedStringExpr ise).getAnInsert()
      or
      exists(AddExpr add | add.getType() instanceof StringType | this = add.getAnOperand())
    )
  }
}

/** Holds if `sink` is a message written to a log. */
private predicate logSink(DataFlow::Node sink) {
  sink instanceof LogMessageSink
  or
  sink instanceof TraceMessageSink
  or
  exists(MethodCall mc |
    mc.getTarget().getDeclaringType().hasFullyQualifiedName("System", "Console") and
    mc.getTarget().getName() in ["Write", "WriteLine"] and
    sink.asExpr() = mc.getAnArgument()
  )
  or
  // log4net, NLog and Serilog loggers that do not derive from an `ILogger` type
  exists(MethodCall mc, Type t |
    t = [mc.getQualifier().getType(), mc.getTarget().getDeclaringType()] and
    t.(RefType)
        .getABaseType*()
        .getNamespace()
        .getFullName()
        .regexpMatch("(log4net|NLog|Serilog)(\\..*)?") and
    mc.getTarget()
        .getName()
        .regexpMatch("(Debug|Info|Warn|Warning|Error|Fatal|Trace|Verbose|Information|Log|Write)(Format)?") and
    sink.asExpr() = mc.getAnArgument()
  )
}

/** A literal HTML comment that contains a password or pwd assignment. */
private class HtmlCommentCredentialLiteral extends StringLiteral {
  HtmlCommentCredentialLiteral() {
    this.getValue().regexpMatch("(?is).*<!--.*\\b(password|pwd)\\s*=\\s*[^;\\s>]+.*-->.*")
  }
}

/** Holds if `e` is data written into an HTTP response or generated Razor output. */
private predicate clientResponseWrite(Expr e) {
  exists(MethodCall mc |
    mc.getTarget().getName() in ["Write", "WriteLiteral"] and
    mc.getTarget()
        .getDeclaringType()
        .getABaseType*()
        .hasFullyQualifiedName(["System.Web", "Microsoft.AspNetCore.Mvc.Razor"],
          ["HttpResponse", "RazorPageBase", "WebPageExecutingBase"]) and
    e = mc.getArgument(0)
  )
}

/** Holds if `write` outputs a credential literal or expression inside an HTML comment. */
private predicate htmlCommentCredentialWrite(Expr write, Expr source) {
  exists(MethodCall mc, InterpolatedStringExpr interpolated, StringLiteral text, Expr credential |
    interpolated = mc.getArgument(0) and
    clientResponseWrite(interpolated) and
    text = interpolated.getAText() and
    text.getValue().regexpMatch("(?is).*<!--.*") and
    credential = interpolated.getAnInsert() and
    credential instanceof CredentialExpr and
    write = mc and
    source = credential
  )
  or
  exists(MethodCall mc, HtmlCommentCredentialLiteral literal |
    mc.getArgument(0) = literal and
    clientResponseWrite(literal) and
    write = mc and
    source = literal
  )
}

/** Holds if `call` enables Entity Framework sensitive-data logging. */
private predicate enablesSensitiveDataLogging(MethodCall call) {
  call.getTarget().hasName("EnableSensitiveDataLogging") and
  call.getTarget().getDeclaringType().getNamespace().getFullName() = "Microsoft.EntityFrameworkCore" and
  not exists(BoolLiteral disabled |
    disabled = call.getArgument(0) and
    disabled.getValue() = "false"
  )
}

/** Holds if `call` hashes data with MD5. */
private predicate md5HashCall(MethodCall call) {
  call.getTarget().getName() in ["ComputeHash", "HashData"] and
  (
    call.getTarget()
        .getDeclaringType()
        .hasFullyQualifiedName("System.Security.Cryptography", ["MD5", "MD5CryptoServiceProvider"])
    or
    call.getQualifier()
        .getType()
        .(RefType)
        .getABaseType*()
        .hasFullyQualifiedName("System.Security.Cryptography", ["MD5", "MD5CryptoServiceProvider"])
    or
    call.getQualifier().getType().getName().regexpMatch("(?i).*MD5.*")
  )
}

private module WeakPasswordHashConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof CredentialExpr }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      md5HashCall(call) and
      sink.asExpr() = call.getArgument(0)
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodCall getBytes |
      getBytes.getTarget().hasName("GetBytes") and
      getBytes.getTarget().getDeclaringType().hasFullyQualifiedName("System.Text", "Encoding") and
      node1.asExpr() = getBytes.getArgument(0) and
      node2.asExpr() = getBytes
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    isProtectionBarrier(node) and not md5HashCall(node.asExpr().(MethodCall))
  }
}

private module WeakPasswordHashFlow = DataFlow::Global<WeakPasswordHashConfig>;

/** A string literal for a connection string that embeds a non-empty `Password` or `Pwd` value. */
private class PasswordConnectionString extends StringLiteral {
  PasswordConnectionString() {
    this.getValue().regexpMatch("(?is).*\\b(password|pwd)\\s*=\\s*[^;\\s{'\"].*")
  }
}

private module CredentialToStringLogConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof CredentialStringConversion
  }

  predicate isSink(DataFlow::Node sink) { logSink(sink) }

  predicate isBarrier(DataFlow::Node node) { isProtectionBarrier(node) }
}

private module CredentialToStringLogFlow = TaintTracking::Global<CredentialToStringLogConfig>;

private module CredentialLogConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof CredentialExpr and
    // reported through the `ToString()` call or conversion instead
    not source.getEnclosingCallable() instanceof CredentialToString
    or
    source.asExpr() instanceof PasswordConnectionString
  }

  predicate isSink(DataFlow::Node sink) { logSink(sink) }

  predicate isBarrier(DataFlow::Node node) { isProtectionBarrier(node) }
}

private module CredentialLogFlow = TaintTracking::Global<CredentialLogConfig>;

/* ------------------------------------------------------------------------- */
/* CWE-798: hard-coded JWT / token signing key                               */
/* ------------------------------------------------------------------------- */
/** Holds if `e` is the key material passed to a token signing key constructor. */
private predicate signingKeyMaterial(Expr e) {
  exists(ObjectCreation oc |
    oc.getObjectType()
        .hasFullyQualifiedName(["Microsoft.IdentityModel.Tokens", "System.IdentityModel.Tokens"],
          ["SymmetricSecurityKey", "InMemorySymmetricSecurityKey"]) and
    e = oc.getArgument(0)
  )
}

private module HardcodedSigningKeyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Expr e | e = source.asExpr() |
      e instanceof StringLiteral
      or
      e.(FieldAccess).getTarget().(Field).isConst()
    ) and
    source.asExpr().getType() instanceof StringType and
    source.asExpr().getValue() != ""
    or
    exists(ArrayCreation ac | ac = source.asExpr() |
      ac.getArrayType().getElementType() instanceof ByteType and
      ac.hasInitializer() and
      ac.getInitializer().getNumberOfElements() > 0 and
      not exists(Expr element | element = ac.getInitializer().getAnElement() |
        not exists(element.getValue())
      )
    )
  }

  predicate isSink(DataFlow::Node sink) { signingKeyMaterial(sink.asExpr()) }
}

private module HardcodedSigningKeyFlow = TaintTracking::Global<HardcodedSigningKeyConfig>;

/* ------------------------------------------------------------------------- */
/* CWE-312: payment-card number persisted in cleartext                       */
/* ------------------------------------------------------------------------- */
/** Holds if `t` writes an XML document to persistent storage. */
private predicate savesXml(ValueOrRefType t) {
  exists(MethodCall save |
    save.getEnclosingCallable().getDeclaringType() = t and
    save.getTarget().hasName("Save") and
    save.getTarget()
        .getDeclaringType()
        .hasFullyQualifiedName(["System.Xml.Linq", "System.Xml"],
          ["XDocument", "XElement", "XmlDocument"])
  )
}

/** Holds if `e` is a scalar value written into an XML tree that is saved to a file. */
private predicate xmlFileValue(Expr e) {
  savesXml(e.getEnclosingCallable().getDeclaringType()) and
  not e.getType().(RefType).getABaseType*().hasFullyQualifiedName("System.Xml.Linq", "XObject") and
  (
    exists(ObjectCreation oc, int i |
      oc.getObjectType().hasFullyQualifiedName("System.Xml.Linq", ["XElement", "XAttribute"]) and
      e = oc.getArgument(i) and
      i > 0
    )
    or
    exists(Property p |
      propertyWrite(e, p) and
      p.hasName("Value") and
      p.getDeclaringType().hasFullyQualifiedName("System.Xml.Linq", ["XElement", "XAttribute"])
    )
    or
    exists(MethodCall mc |
      mc.getTarget().hasName(["SetValue", "SetElementValue", "SetAttributeValue"]) and
      mc.getTarget().getDeclaringType().getNamespace().hasFullyQualifiedName("System.Xml", "Linq") and
      e = mc.getArgument(mc.getNumberOfArguments() - 1)
    )
  )
}

/** Holds if `e` is a card number written to an Entity Framework entity property. */
private predicate efCardNumberValue(Expr e) {
  exists(Property p |
    propertyWrite(e, p) and
    isEfEntity(p.getDeclaringType()) and
    isCardNumberName(p.getName())
  )
}

private module CardNumberStorageConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof CardNumberExpr }

  predicate isSink(DataFlow::Node sink) {
    efCardNumberValue(sink.asExpr()) or xmlFileValue(sink.asExpr())
  }

  predicate isBarrier(DataFlow::Node node) { isProtectionBarrier(node) }
}

private module CardNumberStorageFlow = TaintTracking::Global<CardNumberStorageConfig>;

/* ------------------------------------------------------------------------- */
/* CWE-319: credential sent over an unencrypted socket                        */
/* ------------------------------------------------------------------------- */
/** Holds if `e` is a raw (non-TLS) network stream, such as `TcpClient.GetStream()`. */
private predicate rawNetworkStream(Expr e) {
  e.(MethodCall).getTarget().hasName("GetStream") and
  e.(MethodCall)
      .getTarget()
      .getDeclaringType()
      .hasFullyQualifiedName("System.Net.Sockets", "TcpClient")
  or
  e.(ObjectCreation).getType().hasFullyQualifiedName("System.Net.Sockets", "NetworkStream")
}

/** Holds if `e` is a writer or stream that sends its data over a raw network stream. */
private predicate rawNetworkWriter(Expr e) {
  exists(Expr stream | rawNetworkStream(stream) |
    DataFlow::localExprFlow(stream, e)
    or
    exists(ObjectCreation oc |
      oc.getType().hasFullyQualifiedName("System.IO", ["StreamWriter", "BinaryWriter"]) and
      DataFlow::localExprFlow(stream, oc.getArgument(0)) and
      DataFlow::localExprFlow(oc, e)
    )
  )
}

/** Holds if `e` is data sent in cleartext over a raw socket or network stream. */
private predicate cleartextNetworkSend(Expr e) {
  exists(MethodCall mc |
    rawNetworkWriter(mc.getQualifier()) and
    mc.getTarget().getName().matches("Write%") and
    e = mc.getArgument(0)
  )
  or
  exists(MethodCall mc |
    mc.getTarget().getDeclaringType().hasFullyQualifiedName("System.Net.Sockets", "Socket") and
    mc.getTarget().getName().matches("Send%") and
    e = mc.getArgument(0)
  )
}

private module CleartextNetworkTransmissionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof CredentialExpr }

  predicate isSink(DataFlow::Node sink) { cleartextNetworkSend(sink.asExpr()) }

  predicate isBarrier(DataFlow::Node node) { isProtectionBarrier(node) }
}

private module CleartextNetworkTransmissionFlow =
  TaintTracking::Global<CleartextNetworkTransmissionConfig>;

/* ------------------------------------------------------------------------- */
/* Combined result                                                            */
/* ------------------------------------------------------------------------- */
/**
 * Holds if `alert` exposes a credential or other sensitive data, as described by `message`,
 * with `related` / `relatedText` filling the `$@` placeholder of `message`.
 */
predicate credentialAndDataExposure(
  Element alert, string message, Element related, string relatedText
) {
  // CWE-523
  credentialFormOverHttp(alert) and
  message = "This HTML form submits a password to $@ over unencrypted HTTP." and
  related = alert and
  relatedText = "an http:// URL"
  or
  // CWE-598
  exists(GetFormLiteral form |
    credentialFormOverGet(form) and
    alert = form and
    message = "This HTML form submits a password using GET, exposing it in the request URL." and
    related = form and
    relatedText = "this form"
  )
  or
  // CWE-200 (Web Forms)
  exists(DataFlow::Node source, DataFlow::Node sink |
    CredentialToWebControlFlow::flow(source, sink) and
    alert = sink.asExpr() and
    message = "A stored credential from $@ is rendered into the HTTP response by a web control." and
    related = source.asExpr() and
    relatedText = "this expression"
  )
  or
  // CWE-200 (Razor views)
  exists(CredentialProperty p |
    razorCredentialRender(alert, p) and
    message = "The credential property $@ is rendered into the HTTP response by this view." and
    related = p and
    relatedText = p.getName()
  )
  or
  exists(CardNumberProperty p |
    razorCardNumberRender(alert, p) and
    message = "The payment-card property $@ is rendered into the HTTP response by this view." and
    related = p and
    relatedText = p.getName()
  )
  or
  // CWE-256 (Entity Framework)
  exists(DataFlow::Node source, DataFlow::Node sink, CredentialProperty p |
    BoundPasswordToEfFlow::flow(source, sink) and
    p = boundCredentialProperty(source) and
    // the password is not replaced (e.g. by a hash) before the entity is persisted
    not exists(AssignExpr write, PropertyAccess target |
      target = write.getLeftOperand() and
      write.getLeftOperand().(PropertyAccess).getTarget().getUnboundDeclaration() = p and
      sameEntity(target.getQualifier(), sink.asExpr()) and
      write.getEnclosingCallable() =
        [sink.asExpr().getEnclosingCallable(), source.asParameter().getCallable()] and
      protectsPersistedPassword(write.getRightOperand(), sink.asExpr(), p)
    ) and
    alert = sink.asExpr() and
    message =
      "The model-bound $@ is persisted with its password property '" + p.getName() + "' unhashed." and
    related = source.asParameter() and
    relatedText = source.asParameter().getName()
  )
  or
  // CWE-256 / CWE-315
  exists(ReversibleEncodingFlow::PathNode source, ReversibleEncodingFlow::PathNode sink |
    ReversibleEncodingFlow::flowPath(source, sink) and
    alert = sink.getNode().asExpr() and
    message =
      "The password from $@ is stored after only a reversible encoding (such as Base64), which provides no protection." and
    related = source.getNode().asExpr() and
    relatedText = "this expression"
  )
  or
  // CWE-257
  exists(DataFlow::Node source, DataFlow::Node sink |
    PasswordEncryptionFlow::flow(source, sink) and
    alert = sink.asExpr() and
    message =
      "The password from $@ is protected with reversible encryption instead of a one-way, salted password hash." and
    related = source.asExpr() and
    relatedText = "this expression"
  )
  or
  // CWE-532
  exists(DataFlow::Node source, DataFlow::Node sink |
    CredentialToStringLogFlow::flow(source, sink) and
    alert = sink.asExpr() and
    message = "This log entry includes $@, whose string representation contains a password." and
    related = source.asExpr() and
    relatedText = "this object"
  )
  or
  // CWE-798
  exists(DataFlow::Node source, DataFlow::Node sink |
    HardcodedSigningKeyFlow::flow(source, sink) and
    alert = sink.asExpr() and
    message = "This token signing key is derived from $@ embedded in the source code." and
    related = source.asExpr() and
    relatedText = "a hard-coded value"
  )
  or
  // CWE-256 (plaintext password bound to an INSERT / UPDATE)
  exists(DataFlow::Node source, DataFlow::Node sink |
    PlaintextPasswordSqlParameterFlow::flow(source, sink) and
    alert = sink.asExpr() and
    message =
      "The password from $@ is stored in the database in plaintext instead of as a salted, one-way hash." and
    related = source.asExpr() and
    relatedText = "this expression"
  )
  or
  // CWE-256 (password read from a plaintext file)
  exists(DataFlow::Node source, DataFlow::Node sink |
    PlaintextCredentialFileFlow::flow(source, sink) and
    alert = sink.asExpr() and
    message = "This connection password is read from $@, where it is stored unprotected." and
    related = source.asExpr() and
    relatedText = "a plaintext file"
  )
  or
  // CWE-257 (stored password recovered)
  exists(DataFlow::Node source, DataFlow::Node sink |
    StoredPasswordRecoveryFlow::flow(source, sink) and
    alert = sink.asExpr() and
    message =
      "The stored password from $@ is decoded back to plaintext, so passwords are stored in a recoverable format." and
    related = source.asExpr() and
    relatedText = "this column"
  )
  or
  // CWE-532 (credential or connection string written to a log)
  exists(DataFlow::Node source, DataFlow::Node sink |
    CredentialLogFlow::flow(source, sink) and
    alert = sink.asExpr() and
    message = "This log entry includes $@, which contains a password." and
    related = source.asExpr() and
    relatedText = "this value"
  )
  or
  // CWE-532 (sensitive data logging enabled for Entity Framework)
  exists(MethodCall call |
    enablesSensitiveDataLogging(call) and
    alert = call and
    message =
      "Entity Framework sensitive-data logging is enabled, which may write credentials and other sensitive values to logs." and
    related = call and
    relatedText = "this call"
  )
  or
  // CWE-615 (credentials included in an HTML comment)
  exists(Expr source, Expr sink |
    htmlCommentCredentialWrite(sink, source) and
    alert = sink and
    message = "This HTTP response includes a password in an HTML comment." and
    related = source and
    relatedText = "this comment"
  )
  or
  // CWE-916 (password hashed with MD5)
  exists(DataFlow::Node source, DataFlow::Node sink, MethodCall call |
    WeakPasswordHashFlow::flow(source, sink) and
    md5HashCall(call) and
    sink.asExpr() = call.getArgument(0) and
    alert = call and
    message = "The password from $@ is hashed with MD5, a fast and unsuitable password hash." and
    related = source.asExpr() and
    relatedText = "this expression"
  )
  or
  // CWE-319
  exists(DataFlow::Node source, DataFlow::Node sink |
    CleartextNetworkTransmissionFlow::flow(source, sink) and
    alert = sink.asExpr() and
    message = "The password from $@ is sent over a network connection that is not encrypted." and
    related = source.asExpr() and
    relatedText = "this expression"
  )
  or
  // CWE-312
  exists(DataFlow::Node source, DataFlow::Node sink |
    CardNumberStorageFlow::flow(source, sink) and
    alert = sink.asExpr() and
    (
      if xmlFileValue(sink.asExpr())
      then message = "The payment card number from $@ is persisted in cleartext to an XML file."
      else
        message =
          "The payment card number from $@ is persisted in cleartext by an Entity Framework entity."
    ) and
    related = source.asExpr() and
    relatedText = "this expression"
  )
}

/** Holds if `value` protects or clears a password, or restores one from another entity. */
private predicate protectsPersistedPassword(
  Expr value, Expr persistedEntity, CredentialProperty passwordProperty
) {
  exists(Call c |
    c = value and
    isProtectingCallable(c.getTarget())
  )
  or
  value instanceof NullLiteral
  or
  exists(StringLiteral literal | literal = value and literal.getValue() = "")
  or
  exists(PropertyAccess storedValue |
    storedValue = value and
    storedValue.getTarget().getUnboundDeclaration() = passwordProperty and
    exists(storedValue.getQualifier()) and
    not sameEntity(storedValue.getQualifier(), persistedEntity)
  )
}

/** Holds if `first` and `second` refer to the same local, parameter, or field. */
private predicate sameEntity(Expr first, Expr second) {
  exists(AssignableRead firstRead, AssignableRead secondRead |
    firstRead = first and
    secondRead = second and
    firstRead.getTarget().getUnboundDeclaration() = secondRead.getTarget().getUnboundDeclaration()
  )
}
