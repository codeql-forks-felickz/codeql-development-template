/**
 * Provides a taint-tracking configuration for reasoning about JSON injection:
 * user-controlled values that are concatenated, interpolated or formatted into
 * JSON text that is then sent as a JSON request body or parsed as JSON.
 */

import csharp
private import semmle.code.csharp.frameworks.Format
private import semmle.code.csharp.security.Sanitizers
private import semmle.code.csharp.security.dataflow.flowsources.FlowSources

/**
 * Holds if `s` looks like a fragment of a JSON object, that is, it contains a
 * quoted member name followed by a colon (for example `{"name":"`).
 */
bindingset[s]
private predicate isJsonLikeText(string s) {
  s.regexpMatch("(?s)(.*[\\{\\[,]\\s*|\\s*)\"[^\"]*\"\\s*:.*")
}

/** An expression that builds JSON text from string fragments and other values. */
abstract class JsonTextConstruction extends Expr {
  /** Gets a value that is inserted into the JSON text without encoding. */
  abstract Expr getAnInsertedValue();
}

private predicate isStringConcatenation(AddExpr e) { e.getType() instanceof StringType }

/** Gets an operand of the string concatenation tree rooted at `e`. */
private Expr getAConcatenationPart(AddExpr e) {
  isStringConcatenation(e) and
  exists(Expr op | op = e.getAnOperand() |
    if isStringConcatenation(op) then result = getAConcatenationPart(op) else result = op
  )
}

/** A string concatenation `a + b + ...` that contains a JSON-like string literal. */
private class JsonConcatenation extends JsonTextConstruction, AddExpr {
  JsonConcatenation() {
    isStringConcatenation(this) and
    not isStringConcatenation(this.getParent()) and
    isJsonLikeText(getAConcatenationPart(this).(StringLiteral).getValue())
  }

  override Expr getAnInsertedValue() {
    result = getAConcatenationPart(this) and
    not result instanceof StringLiteral and
    not result instanceof JsonTextConstruction
  }
}

/** An interpolated string `$"..."` with JSON-like text. */
private class JsonInterpolation extends JsonTextConstruction, InterpolatedStringExpr {
  JsonInterpolation() { isJsonLikeText(this.getAText().getValue()) }

  override Expr getAnInsertedValue() {
    result = this.getAnInsert() and
    not result instanceof JsonTextConstruction
  }
}

/** A call to a format method, such as `string.Format`, with a JSON-like format string. */
private class JsonFormatCall extends JsonTextConstruction, FormatCall {
  JsonFormatCall() { isJsonLikeText(this.getFormatExpr().getValue()) }

  override Expr getAnInsertedValue() {
    (
      exists(ValidFormatString format, int i |
        format = this.getFormatExpr() and
        i = format.getAnInsert() and
        result = this.getSuppliedExpr(i)
      )
      or
      (
        this.hasCollectionExpr() or
        not exists(ValidFormatString format | format = this.getFormatExpr())
      ) and
      exists(int i |
        i >= this.getFirstArgument() and
        result = this.getArgument(i)
      )
    ) and
    not result instanceof JsonTextConstruction
  }
}

/** A data flow sink where text is consumed as JSON. */
abstract class JsonTextSink extends DataFlow::ExprNode { }

/** Holds if `e` is, or creates, a media type that mentions JSON. */
private predicate isJsonMediaType(Expr e) {
  e.getValue().regexpMatch("(?i)\\s*[^/;\\s]+/([^;/]*\\+)?json\\s*(;.*)?")
  or
  e.(ObjectCreation)
      .getObjectType()
      .hasFullyQualifiedName("System.Net.Http.Headers", "MediaTypeHeaderValue") and
  isJsonMediaType(e.(ObjectCreation).getArgument(0))
}

/** The content argument of `new StringContent(content, encoding, mediaType)` with a JSON media type. */
private class JsonStringContentSink extends JsonTextSink {
  JsonStringContentSink() {
    exists(ObjectCreation oc |
      oc.getObjectType().hasFullyQualifiedName("System.Net.Http", "StringContent") and
      this.getExpr() = oc.getArgument(0) and
      isJsonMediaType(oc.getAnArgument())
    )
  }
}

/** The text argument of a method that parses or deserializes JSON text. */
private class JsonParseSink extends JsonTextSink {
  JsonParseSink() {
    exists(MethodCall mc, Method m | m = mc.getTarget() |
      (
        m.getDeclaringType().hasFullyQualifiedName("System.Text.Json", "JsonDocument") and
        m.getUndecoratedName() = "Parse"
        or
        m.getDeclaringType().hasFullyQualifiedName("System.Text.Json.Nodes", "JsonNode") and
        m.getUndecoratedName() = "Parse"
        or
        m.getDeclaringType().hasFullyQualifiedName("System.Text.Json", "JsonSerializer") and
        m.getUndecoratedName() = "Deserialize"
        or
        m.getDeclaringType().hasFullyQualifiedName("Newtonsoft.Json", "JsonConvert") and
        m.getUndecoratedName() = ["DeserializeObject", "PopulateObject"]
        or
        m.getDeclaringType()
            .hasFullyQualifiedName("Newtonsoft.Json.Linq", ["JToken", "JObject", "JArray"]) and
        m.getUndecoratedName() = "Parse"
      ) and
      m.getParameter(0).getType() instanceof StringType and
      this.getExpr() = mc.getArgument(0)
    )
  }
}

/** A call that encodes a value so that it cannot change the structure of JSON text. */
private class JsonEncodingCall extends MethodCall {
  JsonEncodingCall() {
    exists(Method m | m = this.getTarget() |
      m.getDeclaringType().hasFullyQualifiedName("System.Text.Json", "JsonSerializer") and
      m.getUndecoratedName() = "Serialize"
      or
      m.getDeclaringType().hasFullyQualifiedName("System.Text.Json", "JsonEncodedText") and
      m.getUndecoratedName() = "Encode"
      or
      m.getDeclaringType()
          .getABaseType*()
          .hasFullyQualifiedName("System.Text.Encodings.Web", "TextEncoder") and
      this.getQualifier()
          .getType()
          .hasFullyQualifiedName("System.Text.Encodings.Web", "JavaScriptEncoder") and
      m.getUndecoratedName() = "Encode"
      or
      m.getDeclaringType().hasFullyQualifiedName("System.Web", "HttpUtility") and
      m.getUndecoratedName() = "JavaScriptStringEncode"
      or
      m.getDeclaringType().hasFullyQualifiedName("Newtonsoft.Json", "JsonConvert") and
      m.getUndecoratedName() = ["SerializeObject", "ToString"]
    )
  }
}

/** Tracks JSON text from where it is built to where it is consumed as JSON. */
private module JsonTextFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof JsonTextConstruction }

  predicate isSink(DataFlow::Node sink) { sink instanceof JsonTextSink }
}

private module JsonTextFlow = TaintTracking::Global<JsonTextFlowConfig>;

/**
 * A value inserted into JSON text that is sent as a JSON request body or
 * parsed as JSON.
 */
class JsonInjectionSink extends DataFlow::ExprNode {
  JsonInjectionSink() {
    exists(JsonTextConstruction c |
      this.getExpr() = c.getAnInsertedValue() and
      JsonTextFlow::flow(DataFlow::exprNode(c), _)
    )
  }
}

/**
 * A taint-tracking configuration for user-controlled values inserted into JSON text.
 */
module JsonInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof JsonInjectionSink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof SimpleTypeSanitizedExpr or
    node instanceof GuidSanitizedExpr or
    node.asExpr() instanceof JsonEncodingCall
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Taint tracking for user-controlled values inserted into JSON text. */
module JsonInjectionFlow = TaintTracking::Global<JsonInjectionConfig>;
