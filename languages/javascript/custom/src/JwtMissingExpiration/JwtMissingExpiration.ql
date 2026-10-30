/**
 * @name JWT issued without expiration
 * @description Signing a JSON Web Token whose payload has no expiration ('exp') claim produces a
 *              token that stays valid forever, so it cannot expire after logout or compromise.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id js/jwt-missing-expiration
 * @tags security
 *       external/cwe/cwe-613
 */

import javascript

/**
 * Holds if `call` may set property `prop` on the object passed as argument `i`, because the
 * corresponding parameter of a callee has a write to `prop`, either directly or by passing the
 * parameter on to another such call.
 */
predicate calleeWritesProperty(DataFlow::InvokeNode call, int i, string prop) {
  exists(DataFlow::FunctionNode f, DataFlow::ParameterNode p |
    f.getFunction() = call.getACallee() and
    p = f.getParameter(i)
  |
    exists(p.getAPropertyWrite(prop))
    or
    exists(DataFlow::InvokeNode inner, int j |
      p.flowsTo(inner.getArgument(j)) and
      calleeWritesProperty(inner, j, prop)
    )
  )
}

/**
 * Holds if `call` may set an unknown property on the object passed as argument `i`, either
 * directly, with `Object.assign`, or by passing the parameter to another such helper.
 */
predicate calleeWritesUnknownProperty(DataFlow::InvokeNode call, int i) {
  exists(DataFlow::FunctionNode f, DataFlow::ParameterNode p |
    f.getFunction() = call.getACallee() and
    p = f.getParameter(i)
  |
    exists(DataFlow::PropWrite pw |
      pw = p.getAPropertyWrite() and not exists(pw.getPropertyName())
    )
    or
    exists(DataFlow::CallNode assign |
      assign = DataFlow::globalVarRef("Object").getAMemberCall("assign") and
      p.flowsTo(assign.getArgument(0))
    )
    or
    exists(DataFlow::InvokeNode inner, int j |
      p.flowsTo(inner.getArgument(j)) and
      calleeWritesUnknownProperty(inner, j)
    )
  )
}

/**
 * Holds if the object literal `obj` may end up with a property named `prop`, either directly,
 * through a later (possibly computed) property write, a spread element, `Object.assign`, or a
 * helper function that writes `prop` on its argument.
 */
bindingset[prop]
predicate mayHaveProperty(DataFlow::ObjectLiteralNode obj, string prop) {
  exists(obj.getAPropertyWrite(prop))
  or
  exists(DataFlow::PropWrite pw | pw = obj.getAPropertyWrite() and not exists(pw.getPropertyName()))
  or
  obj.asExpr().(ObjectExpr).getAProperty() instanceof SpreadProperty
  or
  exists(DataFlow::CallNode assign |
    assign = DataFlow::globalVarRef("Object").getAMemberCall("assign") and
    obj.flowsTo(assign.getArgument(0))
  )
  or
  exists(DataFlow::InvokeNode call, int i |
    obj.flowsTo(call.getArgument(i)) and
    (
      calleeWritesProperty(call, i, prop)
      or
      calleeWritesUnknownProperty(call, i)
    )
  )
}

/** Holds if `opts` is statically known to be `null` or `undefined`. */
predicate isNullishOptions(DataFlow::Node opts) {
  exists(Expr e | e = opts.asExpr().getUnderlyingValue() |
    e instanceof NullLiteral
    or
    e instanceof VoidExpr
    or
    exists(GlobalVarAccess access | e = access and access.getName() = "undefined")
  )
}

/**
 * Holds if `opts` is a known object literal or callback, so that the absence of `prop` in it can
 * be established. Options of unknown origin are conservatively assumed to set `prop`.
 */
bindingset[prop]
predicate optionsLackProperty(DataFlow::Node opts, string prop) {
  exists(opts.getALocalSource()) and
  forall(DataFlow::SourceNode src | src = opts.getALocalSource() |
    src instanceof DataFlow::FunctionNode
    or
    src instanceof DataFlow::ObjectLiteralNode and not mayHaveProperty(src, prop)
  )
}

/** A call that signs a JWT and does not configure an expiration outside of the payload. */
abstract class JwtSigningWithoutExpiryOption extends DataFlow::Node {
  /** Gets the node holding the JWT payload (the claims set). */
  abstract DataFlow::Node getPayload();

  /** Gets a description of the signing API, for use in alert messages. */
  abstract string getApiName();
}

/** A call to `encode` from `jwt-simple`, which has no expiration option. */
class JwtSimpleEncode extends JwtSigningWithoutExpiryOption, DataFlow::CallNode {
  JwtSimpleEncode() { this = API::moduleImport("jwt-simple").getMember("encode").getACall() }

  override DataFlow::Node getPayload() { result = this.getArgument(0) }

  override string getApiName() { result = "jwt-simple encode" }
}

/** A call to `sign` from `jsonwebtoken` without an `expiresIn` option. */
class JsonWebTokenSign extends JwtSigningWithoutExpiryOption, DataFlow::CallNode {
  JsonWebTokenSign() {
    this = API::moduleImport("jsonwebtoken").getMember("sign").getACall() and
    (
      not exists(this.getArgument(2))
      or
      isNullishOptions(this.getArgument(2))
      or
      optionsLackProperty(this.getArgument(2), "expiresIn")
    )
  }

  override DataFlow::Node getPayload() { result = this.getArgument(0) }

  override string getApiName() { result = "jsonwebtoken sign" }
}

/**
 * Gets a reference to the `SignJWT` builder created by `n`, following the fluent setters of the
 * `jose` library which return the builder itself.
 */
DataFlow::SourceNode joseBuilder(DataFlow::NewNode n) {
  n = API::moduleImport("jose").getMember("SignJWT").getAnInstantiation() and
  result = n
  or
  result =
    joseBuilder(n)
        .getAMethodCall([
            "setProtectedHeader", "setIssuer", "setSubject", "setAudience", "setJti",
            "setNotBefore", "setIssuedAt", "setExpirationTime"
          ])
}

/** Holds if the `SignJWT` builder created by `n` escapes the local scope. */
predicate joseBuilderEscapes(DataFlow::NewNode n) {
  exists(DataFlow::Node use | joseBuilder(n).flowsTo(use) |
    use = any(DataFlow::InvokeNode call).getAnArgument()
    or
    use = any(DataFlow::PropWrite pw).getRhs()
    or
    use.asExpr() = any(Function f).getAReturnedExpr()
  )
}

/** A call to `sign` on a `jose` `SignJWT` builder that never calls `setExpirationTime`. */
class JoseSignJwt extends JwtSigningWithoutExpiryOption, DataFlow::MethodCallNode {
  DataFlow::NewNode builder;

  JoseSignJwt() {
    this = joseBuilder(builder).getAMethodCall("sign") and
    not exists(joseBuilder(builder).getAMethodCall("setExpirationTime")) and
    not joseBuilderEscapes(builder)
  }

  override DataFlow::Node getPayload() { result = builder.getArgument(0) }

  override string getApiName() { result = "jose SignJWT" }
}

/**
 * A data-flow configuration tracking object literals without an `exp` property to the payload
 * of a JWT signing call that does not otherwise configure an expiration.
 */
module JwtPayloadWithoutExpConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof DataFlow::ObjectLiteralNode and
    not mayHaveProperty(source, "exp")
  }

  predicate isSink(DataFlow::Node sink) { sink = any(JwtSigningWithoutExpiryOption s).getPayload() }

  predicate isBarrier(DataFlow::Node node) {
    // A parameter or other local source on which `exp` is written, for example in a helper
    // that adds the claim and returns the payload.
    exists(node.getALocalSource().getAPropertyWrite("exp"))
  }
}

module JwtPayloadWithoutExpFlow = DataFlow::Global<JwtPayloadWithoutExpConfig>;

from JwtSigningWithoutExpiryOption signing, DataFlow::Node payload, DataFlow::Node sink
where
  JwtPayloadWithoutExpFlow::flow(payload, sink) and
  sink = signing.getPayload()
select signing,
  "This JWT is signed with " + signing.getApiName() +
    " without an expiration, because its $@ has no 'exp' claim.", payload, "payload"
