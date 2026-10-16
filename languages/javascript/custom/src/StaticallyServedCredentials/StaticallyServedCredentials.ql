/**
 * @name Hard-coded credential in a statically served directory
 * @description A file inside a directory that is served to the public by a static-file
 *              middleware contains what looks like a hard-coded credential. Anyone who can
 *              reach the server can download the file and read the credential.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision medium
 * @id js/statically-served-credentials
 * @tags security
 *       external/cwe/cwe-798
 *       external/cwe/cwe-200
 *       external/cwe/cwe-538
 */

import javascript
import codeql.concepts.internal.SensitiveDataHeuristics
import StaticFileServing.StaticFileServing

/**
 * Holds if `value` looks like a plausible hard-coded credential value.
 */
bindingset[value]
predicate isCredentialValue(string value) { value.regexpMatch("\\S+") }

/**
 * Holds if `name` looks like the name of a password or secret.
 */
bindingset[name]
predicate isCredentialName(string name) {
  HeuristicNames::nameIndicatesSensitiveData(name,
    [SensitiveDataClassification::password(), SensitiveDataClassification::secret()])
}

/**
 * Holds if `elt` is a hard-coded credential named `name` in an extracted file.
 */
predicate hardcodedCredential(Locatable elt, string name) {
  // JavaScript: `{ password: "..." }`, `exports.password = "..."`
  exists(DataFlow::PropWrite pw, ConstantString value |
    pw.getPropertyName() = name and
    pw.getRhs().asExpr() = value and
    isCredentialValue(value.getStringValue()) and
    elt = pw.getAstNode()
  ) and
  isCredentialName(name) and
  not elt.(AstNode).getTopLevel().isMinified()
  or
  // JavaScript: `var password = "..."`
  exists(VariableDeclarator decl |
    name = decl.getBindingPattern().(VarDecl).getName() and
    isCredentialValue(decl.getInit().(ConstantString).getStringValue()) and
    elt = decl
  ) and
  isCredentialName(name) and
  not elt.(AstNode).getTopLevel().isMinified()
  or
  // JSON: `{ "password": "..." }`
  exists(JsonObject obj |
    isCredentialValue(obj.getPropStringValue(name)) and
    elt = obj.getPropValue(name)
  ) and
  isCredentialName(name)
  or
  // YAML: `password: ...`
  exists(YamlMapping map, YamlScalar key, YamlScalar value |
    map.maps(key, value) and
    name = key.getValue() and
    isCredentialValue(value.getValue()) and
    elt = value
  ) and
  isCredentialName(name)
}

from Locatable cred, string name, File f, DataFlow::CallNode serve
where
  hardcodedCredential(cred, name) and
  f = cred.getFile() and
  serve =
    min(DataFlow::CallNode s |
      isServedPath(f.getRelativePath(), s)
    |
      s order by s.getFile().getRelativePath(), s.getStartLine(), s.getStartColumn()
    )
select cred,
  "Hard-coded credential '" + name + "' in " + f.getRelativePath() +
    " is exposed to the public by $@.", serve, "this static-file middleware"
