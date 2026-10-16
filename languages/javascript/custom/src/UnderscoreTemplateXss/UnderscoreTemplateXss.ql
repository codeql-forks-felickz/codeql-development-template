/**
 * @name Client-side cross-site scripting through an unescaped Underscore template interpolation
 * @description Interpolating untrusted data with the unescaped `<%= %>` delimiter of an
 *              Underscore or lodash template inserts it into the page as raw HTML,
 *              allowing cross-site scripting.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision medium
 * @id js/underscore-template-xss
 * @tags security
 *       frameworks/backbone
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript
import semmle.javascript.security.dataflow.DomBasedXssCustomizations
import UnderscoreTemplateXssFlow::PathGraph

/**
 * Underscore/lodash template syntax: `<%= x %>` interpolates without escaping and
 * `<%- x %>` HTML-escapes (the opposite of EJS).
 */
class UnderscoreTemplateSyntax extends Templating::TemplateSyntax {
  UnderscoreTemplateSyntax() { this = "underscore" }

  override string getRawInterpolationRegexp() { result = "(?s)<%=(.*?)%>" }

  override string getEscapingInterpolationRegexp() { result = "(?s)<%-(.*?)%>" }

  // Only applied to files resolved from an `_.template` instantiation.
  override string getAFileExtension() { none() }

  override string getAPackageName() { none() }
}

/** Gets a function that is a property value of the object literal `obj`. */
DataFlow::FunctionNode getAMethodOf(DataFlow::ObjectLiteralNode obj) {
  result = obj.getAPropertySource()
}

/** Gets an object literal passed to `Backbone.View.extend(...)`. */
DataFlow::ObjectLiteralNode backboneViewDefinition() {
  exists(DataFlow::CallNode extend |
    extend = DataFlow::moduleMember("backbone", "View").getAMemberCall("extend")
    or
    extend = DataFlow::globalVarRef("Backbone").getAPropertyRead("View").getAMemberCall("extend")
  |
    result = extend.getArgument(0).getALocalSource()
  )
}

/** A call to `_.template(tmpl)`, returning a compiled template function. */
class UnderscoreTemplateCompilation extends DataFlow::CallNode {
  UnderscoreTemplateCompilation() { this = LodashUnderscore::member("template").getACall() }

  /** Gets a call of the compiled template function. */
  DataFlow::CallNode getATemplateCall() {
    result = this.getACall()
    or
    // Backbone convention: `template: _.template(tmpl)` called as `this.template(data)`.
    exists(DataFlow::ObjectLiteralNode view, string prop |
      view = backboneViewDefinition() and
      view.getAPropertySource(prop) = this and
      result = getAMethodOf(view).getReceiver().getAMethodCall(prop)
    )
  }

  /**
   * Gets the `text!`-plugin AMD dependency string that provides the template source,
   * as in `define(['text!templates/x.html'], function (Tpl) { _.template(Tpl) })`.
   */
  Expr getTemplateDependency() {
    exists(AmdModuleDefinition amd, Parameter p |
      amd.dependencyParameter(result, p) and
      result.getStringValue().matches("text!%") and
      DataFlow::parameterNode(p) = this.getArgument(0).getALocalSource()
    )
  }
}

/** A reference to a template file through the RequireJS `text!` plugin. */
class TextPluginTemplateFileReference extends Templating::TemplateFileReference {
  TextPluginTemplateFileReference() {
    this.asExpr() = any(UnderscoreTemplateCompilation c).getTemplateDependency()
  }

  override string getValue() { result = this.getStringValue().suffix("text!".length()) }
}

/** An invocation of a compiled Underscore/lodash template loaded from a template file. */
class UnderscoreTemplateInstantiation extends Templating::TemplateInstantiation::Range,
  DataFlow::CallNode
{
  UnderscoreTemplateCompilation compilation;

  UnderscoreTemplateInstantiation() {
    this = compilation.getATemplateCall() and exists(compilation.getTemplateDependency())
  }

  override DataFlow::SourceNode getOutput() { result = this }

  override DataFlow::Node getTemplateFileNode() {
    result.asExpr() = compilation.getTemplateDependency()
  }

  override DataFlow::Node getTemplateParamsNode() { result = this.getArgument(0) }

  override Templating::TemplateSyntax getTemplateSyntax() {
    result instanceof UnderscoreTemplateSyntax
  }
}

/** Gets a use of the free variable `name` inside a placeholder tag of `file`. */
DataFlow::Node templateVariableUse(Templating::TemplateFile file, string name) {
  result = file.getAPlaceholder().getInnerTopLevel().getAVariableUse(name)
}

/**
 * Holds if a scriptlet in `file` iterates over the template variable `collection`,
 * binding each element to `element`, as in `<% _(users).each(function(user) { %>`.
 *
 * Scriptlets that open a block are not valid JavaScript on their own, so they are
 * matched textually.
 */
predicate templateLoop(Templating::TemplateFile file, string collection, string element) {
  exists(string text |
    text = file.getAPlaceholder().getRawText() and
    text.regexpMatch("(?s)<%[^=-].*")
  |
    exists(string m |
      m =
        text.regexpFind("_\\(\\s*\\w+\\s*\\)\\s*\\.\\s*(each|forEach|map)\\s*\\(\\s*function\\s*\\(\\s*\\w+",
          _, _) and
      collection = m.regexpCapture("_\\(\\s*(\\w+).*", 1) and
      element = m.regexpCapture("(?s).*function\\s*\\(\\s*(\\w+)", 1)
      or
      m = text.regexpFind("_\\.(each|forEach|map)\\(\\s*\\w+\\s*,\\s*function\\s*\\(\\s*\\w+", _, _) and
      collection = m.regexpCapture("_\\.\\w+\\(\\s*(\\w+).*", 1) and
      element = m.regexpCapture("(?s).*function\\s*\\(\\s*(\\w+)", 1)
      or
      m = text.regexpFind("\\b\\w+\\s*\\.\\s*(forEach|map)\\s*\\(\\s*function\\s*\\(\\s*\\w+", _, _) and
      collection = m.regexpCapture("(\\w+).*", 1) and
      element = m.regexpCapture("(?s).*function\\s*\\(\\s*(\\w+)", 1)
    )
  )
}

/**
 * Holds if `pred` is the value given to the template variable `name` at `inst`,
 * either as a property of an object literal or (when the whole data object is not a
 * literal) as an unknown property of a tainted data object.
 */
predicate templateInput(UnderscoreTemplateInstantiation inst, string name, DataFlow::Node pred) {
  exists(DataFlow::ObjectLiteralNode obj | obj = inst.getTemplateParamsNode().getALocalSource() |
    pred = obj.getAPropertyWrite(name).getRhs()
  )
  or
  not inst.getTemplateParamsNode().getALocalSource() instanceof DataFlow::ObjectLiteralNode and
  pred = inst.getTemplateParamsNode() and
  name =
    templateVariableUse(inst.(Templating::TemplateInstantiation).getTemplateFile(), _)
        .asExpr()
        .(VarRef)
        .getName() and
  not name = "_"
}

/**
 * Data of a Backbone model or collection, for example `this.model.toJSON()` or
 * `this.collection.get(id)` inside a `Backbone.View`. This data is typically
 * loaded from the server and may contain values stored by other users.
 */
class BackboneModelData extends DataFlow::Node {
  BackboneModelData() {
    exists(DataFlow::SourceNode modelRef |
      modelRef =
        getAMethodOf(backboneViewDefinition())
            .getReceiver()
            .getAPropertyRead(["model", "collection"])
    |
      this = modelRef.getAMethodCall(["toJSON", "get", "pluck", "where", "findWhere", "at"])
      or
      this = modelRef.getAPropertyRead(["attributes", "models"])
    )
  }
}

module UnderscoreTemplateXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof DomBasedXss::Source
    or
    source instanceof BackboneModelData
    or
    source = any(ClientRequest r).getAResponseDataNode()
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Templating::TemplatePlaceholderTag tag |
      tag.isRawInterpolation() and
      sink = tag.asDataFlowNode() and
      tag.getFile() =
        any(UnderscoreTemplateInstantiation inst)
            .(Templating::TemplateInstantiation)
            .getTemplateFile()
    )
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof DomBasedXss::Sanitizer }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(UnderscoreTemplateInstantiation inst, Templating::TemplateFile file, string name |
      file = inst.(Templating::TemplateInstantiation).getTemplateFile() and
      templateInput(inst, name, pred)
    |
      // `<%= name %>`
      succ = templateVariableUse(file, name)
      or
      // `<% _(name).each(function(elem) { %> ... <%= elem.x %>`
      exists(string element |
        templateLoop(file, name, element) and
        succ = templateVariableUse(file, element)
      )
    )
  }
}

module UnderscoreTemplateXssFlow = TaintTracking::Global<UnderscoreTemplateXssConfig>;

from UnderscoreTemplateXssFlow::PathNode source, UnderscoreTemplateXssFlow::PathNode sink
where UnderscoreTemplateXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Cross-site scripting vulnerability: $@ is interpolated without escaping by an Underscore template.",
  source.getNode(), "this value"
