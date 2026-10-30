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
        isCredentialName(prop)
      )
      or
      exists(DataFlow::PropRead read |
        DataFlow::localFlowStep*(this, read.getBase()) and
        isCredentialName(read.getPropertyName())
      )
    )
  }
}

module SensitiveDataInJwtPayloadConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof CredentialRecord
    or
    source.(SensitiveNode).getClassification() = SensitiveDataClassification::password()
  }

  predicate isSink(DataFlow::Node sink) { sink = jwtPayload() }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet contents) {
    // Every property of a signed payload object ends up in the token.
    isSink(node) and contents = DataFlow::ContentSet::anyProperty()
  }

  predicate isBarrier(DataFlow::Node node) {
    // Reading a non-credential field (e.g. `user.email`) does not expose the credential.
    exists(string prop | prop = node.(DataFlow::PropRead).getPropertyName() |
      not isCredentialName(prop)
    )
    or
    node instanceof ProtectCall
    or
    // The rest of an object after a credential field has been destructured out, as in
    // `const { password, ...profile } = user`.
    exists(ObjectPattern pattern |
      isCredentialName(pattern.getAPropertyPattern().getName()) and
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
