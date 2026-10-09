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

/**
 * Gets a call that creates a middleware serving the folder given as its first argument.
 */
DataFlow::CallNode staticServeCall() {
  result = DataFlow::moduleMember(["express", "connect"], "static").getACall()
  or
  result = DataFlow::moduleImport(["serve-static", "koa-static"]).getACall()
}

/**
 * Holds if `node` is a reference to `__dirname`.
 */
predicate isDirname(DataFlow::Node node) {
  exists(ModuleScope ms | node.asExpr() = ms.getVariable("__dirname").getAnAccess())
}

/**
 * Holds if `node` is the folder argument of a static-file middleware, or flows to one.
 */
predicate isRelevantFolderNode(DataFlow::Node node) {
  node = staticServeCall().getArgument(0)
  or
  exists(DataFlow::Node succ | isRelevantFolderNode(succ) | node = succ.getAPredecessor())
}

/**
 * Gets the `/`-joined string values of the arguments `start..` of `call`, if all of them are
 * constant strings.
 */
string joinedArguments(DataFlow::CallNode call, int start) {
  start in [0, 1] and
  start < call.getNumArgument() and
  forall(int i | i in [start .. call.getNumArgument() - 1] |
    exists(call.getArgument(i).getStringValue())
  ) and
  result =
    concat(int i, string s |
      i in [start .. call.getNumArgument() - 1] and s = call.getArgument(i).getStringValue()
    |
      s, "/" order by i
    )
}

/**
 * Holds if `node` evaluates to the folder path `path`. If `fromDirname` is true, `path` is
 * relative to the folder of the enclosing file, otherwise it is relative to the working
 * directory of the process.
 */
predicate folderPath(DataFlow::Node node, string path, boolean fromDirname) {
  isRelevantFolderNode(node) and
  (
    // `"public"`
    node.getStringValue() = path and
    not path.matches("/%") and
    fromDirname = false
    or
    // `__dirname + "/public"`
    exists(StringOps::ConcatenationRoot root |
      root = node and
      root.getNumOperand() = 2 and
      isDirname(root.getOperand(0)) and
      path = root.getOperand(1).getStringValue() and
      fromDirname = true
    )
    or
    // `path.join(__dirname, "public")`, `path.resolve("public")`
    exists(DataFlow::CallNode join |
      join = node and
      join = DataFlow::moduleMember("path", ["join", "resolve"]).getACall()
    |
      isDirname(join.getArgument(0)) and
      path = joinedArguments(join, 1) and
      fromDirname = true
      or
      path = joinedArguments(join, 0) and
      not path.matches("/%") and
      fromDirname = false
    )
    or
    // local data flow, for example `var dir = "./www"; serveStatic(dir)`
    folderPath(node.getAPredecessor(), path, fromDirname)
  )
}

/**
 * Gets `path` with redundant `.` components and leading, trailing or duplicate slashes removed.
 */
bindingset[path]
string normalize(string path) {
  result =
    ("/" + path + "/")
        .regexpReplaceAll("/+", "/")
        .regexpReplaceAll("/(\\./)+", "/")
        .regexpReplaceAll("^/|/$", "")
}

/**
 * Gets a folder that may be the working directory of a process running a script in `f`:
 * the folder of `f` itself, or an enclosing folder that contains a `package.json` file.
 */
Folder getAWorkingFolder(File f) {
  result = f.getParentContainer()
  or
  result = f.getParentContainer+() and
  result = any(PackageJson json).getFile().getParentContainer()
}

/**
 * Gets the folder that is served to the public by `serve`.
 */
Folder getAServedFolder(DataFlow::CallNode serve) {
  serve = staticServeCall() and
  exists(string path, boolean fromDirname, Folder base, string rel |
    folderPath(serve.getArgument(0), path, fromDirname) and
    rel = normalize(path) and
    not rel.regexpMatch("(.*/)?\\.\\.(/.*)?") and
    (
      fromDirname = true and base = serve.getFile().getParentContainer()
      or
      fromDirname = false and base = getAWorkingFolder(serve.getFile())
    )
  |
    if rel = ""
    then result = base
    else
      if base.getRelativePath() = ""
      then result.getRelativePath() = rel
      else result.getRelativePath() = base.getRelativePath() + "/" + rel
  )
}

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

/**
 * Holds if `f` is served by default as part of `folder`, that is, no path component between
 * `folder` and `f` starts with a dot (dotfiles are ignored by default by static-file middlewares).
 */
predicate isServedFrom(File f, Folder folder) {
  f.getParentContainer+() = folder and
  not f.getRelativePath()
      .suffix(folder.getRelativePath().length())
      .regexpMatch("(.*/)?\\.[^/]*(/.*)?")
}

from Locatable cred, string name, File f, DataFlow::CallNode serve
where
  hardcodedCredential(cred, name) and
  f = cred.getFile() and
  serve =
    min(DataFlow::CallNode s, Folder folder |
      folder = getAServedFolder(s) and isServedFrom(f, folder)
    |
      s order by s.getFile().getRelativePath(), s.getStartLine(), s.getStartColumn()
    )
select cred,
  "Hard-coded credential '" + name + "' in " + f.getRelativePath() +
    " is exposed to the public by $@.", serve, "this static-file middleware"
