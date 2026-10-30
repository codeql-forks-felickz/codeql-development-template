/**
 * @name Sensitive data in JWT payload
 * @description Signing a password, or a whole user record that contains a password,
 *              into a JSON Web Token exposes it to anyone who obtains the token,
 *              because a JWT payload is only Base64-encoded, not encrypted.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id js/sensitive-data-in-jwt-payload
 * @tags security
 *       external/cwe/cwe-522
 *       external/cwe/cwe-312
 */

import javascript
import semmle.javascript.security.SensitiveActions

/** Holds if `name` looks like the name of a password or similar credential. */
bindingset[name]
predicate isCredentialName(string name) {
  name.regexpMatch(HeuristicNames::maybePassword()) and
  not name.regexpMatch(HeuristicNames::notSensitiveRegexp())
}

/** Gets a data flow node that is the payload argument of a JWT signing call. */
DataFlow::Node jwtPayload() {
  result = API::moduleImport("jsonwebtoken").getMember("sign").getParameter(0).asSink()
  or
  result = API::moduleImport("jwt-simple").getMember("encode").getParameter(0).asSink()
  or
  result = API::moduleImport("jose").getMember("SignJWT").getAnInvocation().getArgument(0)
}

/** Gets a result of `access`, including the result parameter of a Node.js-style callback. */
DataFlow::Node databaseResult(DatabaseAccess access) {
  result = access.getAResult()
  or
  exists(DataFlow::CallNode call | call = access |
    result = call.getABoundCallbackParameter(call.getNumArgument() - 1, 1)
  )
}

/** Holds if `prop` is excluded by an explicit MongoDB projection. */
predicate isExcludedByProjection(DatabaseAccess access, string prop) {
  exists(
    DataFlow::CallNode call, DataFlow::Node projectionValue, DataFlow::ObjectLiteralNode projection,
    DataFlow::Node projectedValue
  |
    call = access and
    (
      projectionValue = call.getOptionArgument(_, "projection")
      or
      projectionValue = call.getArgument(1)
    ) and
    projection = projectionValue.getALocalSource() and
    projection.hasPropertyWrite(prop, projectedValue) and
    projectedValue.getIntValue() = 0
  )
}

/**
 * A database record that is known to contain a credential, either because the
 * query that fetched it filters on a credential field, or because a credential
 * field is read from it.
 */
class CredentialRecord extends DataFlow::Node {
  CredentialRecord() {
    exists(DatabaseAccess access | this = databaseResult(access) |
      exists(string prop |
        access
            .getAQueryArgument()
            .getALocalSource()
            .(DataFlow::ObjectLiteralNode)
            .hasPropertyWrite(prop, _) and
        isCredentialName(prop) and
        not isExcludedByProjection(access, prop)
      )
      or
      exists(DataFlow::PropRead read |
        DataFlow::localFlowStep*(this, read.getBase()) and
        isCredentialName(read.getPropertyName()) and
        not isExcludedByProjection(access, read.getPropertyName())
      )
    )
  }
}

/** Holds if `pattern` removes a credential-named property, including nested patterns. */
predicate removesCredential(ObjectPattern pattern) {
  exists(PropertyPattern property |
    property = pattern.getAPropertyPattern() and
    (
      isCredentialName(property.getName())
      or
      exists(ObjectPattern nested |
        nested = property.getValuePattern() and
        removesCredential(nested)
      )
    )
  )
}

module SensitiveDataInJwtPayloadConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof CredentialRecord
    or
    source.(SensitiveNode).getClassification() = SensitiveDataClassification::password()
  }

  predicate isSink(DataFlow::Node sink) { sink = jwtPayload() }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(
      ObjectPattern pattern, VariableDeclarator decl, DataFlow::ObjectLiteralNode object, Expr init,
      string prop
    |
      decl.getBindingPattern() = pattern and
      init = decl.getInit() and
      object = DataFlow::valueNode(init).getALocalSource() and
      object.hasPropertyWrite(prop, pred) and
      not exists(PropertyPattern removed |
        removed = pattern.getAPropertyPattern() and removed.getName() = prop
      ) and
      succ = DataFlow::lvalueNode(pattern.getRest())
    )
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet contents) {
    // Every property of a signed payload object ends up in the token.
    isSink(node) and contents = DataFlow::ContentSet::anyProperty()
  }

  predicate isBarrier(DataFlow::Node node) {
    // Reading a non-credential leaf field (e.g. `user.email`) does not expose the credential.
    exists(DataFlow::PropRead read, DatabaseAccess access |
      read = node and
      not isCredentialName(read.getPropertyName()) and
      DataFlow::localFlowStep*(databaseResult(access), read.getBase()) and
      not exists(DataFlow::PropRead nested |
        DataFlow::localFlowStep*(read, nested.getBase()) and
        isCredentialName(nested.getPropertyName())
      )
    )
    or
    node instanceof ProtectCall
    or
    // The rest of a database record after a credential-containing field is removed.
    exists(ObjectPattern pattern, VariableDeclarator decl, DatabaseAccess access |
      decl.getBindingPattern() = pattern and
      exists(Expr init |
        init = decl.getInit() and
        DataFlow::localFlowStep*(databaseResult(access), DataFlow::valueNode(init))
      ) and
      removesCredential(pattern) and
      node = DataFlow::lvalueNode(pattern.getRest())
    )
  }
}

module SensitiveDataInJwtPayloadFlow = TaintTracking::Global<SensitiveDataInJwtPayloadConfig>;

import SensitiveDataInJwtPayloadFlow::PathGraph

from SensitiveDataInJwtPayloadFlow::PathNode source, SensitiveDataInJwtPayloadFlow::PathNode sink
where SensitiveDataInJwtPayloadFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This JWT payload includes $@, which is readable by anyone holding the token.", source.getNode(),
  "sensitive data"
