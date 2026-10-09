/**
 * @name Hard-coded password in model creation
 * @description A hard-coded string literal is used as the password attribute of an
 *              ActiveRecord model created by the application (for example in seed data).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision medium
 * @id rb/hardcoded-password-model-creation
 * @tags security
 *       external/cwe/cwe-259
 *       external/cwe/cwe-798
 */

import codeql.ruby.AST
import codeql.ruby.ApiGraphs
import codeql.ruby.DataFlow

/** Holds if `name` is the name of an attribute that holds a plaintext password. */
bindingset[name]
private predicate isPasswordAttributeName(string name) {
  name.regexpMatch("(?i)([a-z0-9]+_)*pass(wd|word|phrase)(_confirmation)?")
}

/** Gets an ActiveRecord base class that application models inherit from. */
private API::Node activeRecordBase() {
  result =
    [
      API::getTopLevelMember("ActiveRecord").getMember("Base"),
      API::getTopLevelMember("ApplicationRecord")
    ]
}

/** A call that creates (or instantiates) an ActiveRecord model from a hash of attributes. */
private class ModelCreationCall extends DataFlow::CallNode {
  ModelCreationCall() {
    this =
      activeRecordBase()
          .getAMethodCall([
              "new", "create", "create!", "create_or_find_by", "create_or_find_by!",
              "find_or_create_by", "find_or_create_by!", "find_or_initialize_by", "insert",
              "insert!"
            ])
  }
}

/** Holds if `e` is the value of a hash pair (or keyword argument) with a password key. */
private predicate isPasswordPairValue(Expr e) {
  exists(Pair p |
    p.getValue() = e and
    isPasswordAttributeName(p.getKey().getConstantValue().getStringlikeValue())
  )
}

/**
 * Holds if `sink` is the value of a password pair passed directly as an argument to a model
 * creation call, such as `User.create(password: "...")` or `User.new("password" => "...")`.
 */
private predicate isPasswordKeywordArgument(DataFlow::Node sink) {
  exists(ModelCreationCall call, Pair p |
    p = call.asExpr().getExpr().(MethodCall).getAnArgument() and
    isPasswordAttributeName(p.getKey().getConstantValue().getStringlikeValue()) and
    sink.asExpr().getExpr() = p.getValue()
  )
}

/** A non-empty string literal. */
private class StringLiteralSource extends DataFlow::Node {
  StringLiteralSource() {
    exists(StringLiteral sl | sl = this.asExpr().getExpr() |
      sl.getConstantValue().getString() != ""
    )
  }
}

private module HardcodedPasswordConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof StringLiteralSource }

  predicate isSink(DataFlow::Node sink) {
    // User.create(password: "...")
    isPasswordKeywordArgument(sink)
    or
    // User.create(attrs), where `attrs[:password]` holds the value
    sink = any(ModelCreationCall call).getArgument(0)
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    isSink(node) and
    exists(DataFlow::Content::KnownElementContent kc |
      c.isSingleton(kc) and
      isPasswordAttributeName(kc.getIndex().getStringlikeValue())
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

private module HardcodedPasswordFlow = DataFlow::Global<HardcodedPasswordConfig>;

import HardcodedPasswordFlow::PathGraph

from HardcodedPasswordFlow::PathNode source, HardcodedPasswordFlow::PathNode sink
where
  HardcodedPasswordFlow::flowPath(source, sink) and
  // For attribute hashes, only report literals that are stored under a password key, so
  // that a literal reaching the attribute hash itself is not reported.
  (
    isPasswordKeywordArgument(sink.getNode())
    or
    isPasswordPairValue(source.getNode().asExpr().getExpr())
  )
select source.getNode(), source, sink, "This hardcoded value is $@.", sink.getNode(),
  "used as a model password attribute"
