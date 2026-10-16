/**
 * @name Use of insufficient randomness as key material
 * @description Storing or returning a value produced by a cryptographically weak
 *              random number generator as a key, secret, token, nonce or salt
 *              allows an attacker to predict it.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision medium
 * @id go/insecure-randomness-key-material
 * @tags security
 *       external/cwe/cwe-338
 */

import go
import semmle.go.security.InsecureRandomness

/**
 * Gets a regular expression matching names that heuristically denote
 * cryptographic key material or other security-sensitive random values.
 */
string keyMaterialName() {
  result =
    "(?i).*((crypt|cipher|secret|private|signing|sign|hmac|aes|session|message|msg|master|api|auth|access|shared|symmetric)_?keys?"
      + "|secret|nonce|salt" +
      "|(auth|access|session|csrf|xsrf|reset|refresh|api|bearer|verification|verify|secure|random)_?tokens?).*"
}

/** Holds if `e` is (a selector or index into) an entity whose name denotes key material. */
predicate isKeyMaterialLhs(Expr e) {
  e.(Ident).getName().regexpMatch(keyMaterialName())
  or
  e.(SelectorExpr).getSelector().getName().regexpMatch(keyMaterialName())
  or
  isKeyMaterialLhs(e.(SelectorExpr).getBase())
  or
  isKeyMaterialLhs(e.(IndexExpr).getBase())
  or
  isKeyMaterialLhs(e.(StarExpr).getBase())
  or
  isKeyMaterialLhs(e.(ParenExpr).getExpr())
}

/**
 * A value that is stored in, or returned as, key material, based on the name of the
 * variable, field or function involved.
 */
class KeyMaterialSink extends DataFlow::Node {
  KeyMaterialSink() {
    // `key = v`, `x.MessageKey.Value = v`, `keys[i] = v`
    exists(Assignment a, int i |
      this.asExpr() = a.getRhs(i) and
      isKeyMaterialLhs(a.getLhs(i))
    )
    or
    // `var secret = v`
    exists(ValueSpec spec, int i |
      this.asExpr() = spec.getInit(i) and
      spec.getNameExpr(i).getName().regexpMatch(keyMaterialName())
    )
    or
    // `T{SessionToken: v}`
    exists(KeyValueExpr kv |
      kv.getParent() instanceof StructLit and
      this.asExpr() = kv.getValue() and
      kv.getKey().(Ident).getName().regexpMatch(keyMaterialName())
    )
    or
    // `func generateApiToken() string { ...; return v }`
    exists(FuncDecl f |
      f.getName().regexpMatch(keyMaterialName()) and
      this.asExpr() = f.getBody().getAStmt*().(ReturnStmt).getAnExpr() and
      this.asExpr().getEnclosingFunction() = f
    )
  }
}

module KeyMaterialConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof InsecureRandomness::Source and
    // Avoid duplicating results of the standard `go/insecure-randomness` query.
    not InsecureRandomness::Flow::flow(source, _)
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof KeyMaterialSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof InsecureRandomness::Sanitizer }

  predicate isBarrierOut(DataFlow::Node node) { isSink(node) }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    // As in `go/insecure-randomness`: selecting an element of a fixed set with a weak index.
    n1.asExpr() = n2.asExpr().(IndexExpr).getIndex() and
    (
      n2.getType() instanceof StringType or
      n2.getType() instanceof IntegerType
    )
    or
    // Arithmetic on a weak random value (e.g. `rand.Intn(100) + 1`) is still weak.
    n1.asExpr() = n2.asExpr().(ArithmeticBinaryExpr).getAnOperand()
  }
}

module KeyMaterialFlow = TaintTracking::Global<KeyMaterialConfig>;

import KeyMaterialFlow::PathGraph

from KeyMaterialFlow::PathNode source, KeyMaterialFlow::PathNode sink
where KeyMaterialFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This key material depends on a $@ generated with a cryptographically weak RNG.",
  source.getNode(), "random number"
