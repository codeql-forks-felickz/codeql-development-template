/**
 * Provides predicates for resolving the folders that are served to the public by static-file
 * middlewares such as `express.static`, `serve-static` and `koa-static`, and for resolving
 * other file-system paths (view folders, `res.sendFile` targets) relative to the source root.
 */

import javascript

/**
 * Gets a call that creates a middleware serving the folder given as its first argument.
 */
DataFlow::CallNode staticServeCall() {
  result = DataFlow::moduleMember(["express", "connect"], "static").getACall()
  or
  result = DataFlow::moduleImport(["serve-static", "koa-static"]).getACall()
}

/**
 * Gets a call `app.set("views", folder)` that configures the Express views folder.
 */
DataFlow::MethodCallNode viewsSetting() {
  result = DataFlow::moduleImport("express").getACall().getAMethodCall("set") and
  result.getArgument(0).mayHaveStringValue("views")
}

/**
 * Gets a call to `res.sendFile` (or the deprecated `res.sendfile`) in an Express route handler.
 */
DataFlow::MethodCallNode sendFileCall() {
  result.getMethodName() = ["sendFile", "sendfile"] and
  result.getReceiver() instanceof Express::ResponseNode
}

/**
 * Holds if `node` is a reference to `__dirname`.
 */
predicate isDirname(DataFlow::Node node) {
  exists(ModuleScope ms | node.asExpr() = ms.getVariable("__dirname").getAnAccess())
}

/**
 * Holds if `node` is a file-system path argument that should be resolved, or flows to one.
 */
private predicate isRelevantPathNode(DataFlow::Node node) {
  node = staticServeCall().getArgument(0)
  or
  node = viewsSetting().getArgument(1)
  or
  node = sendFileCall().getArgument(0)
  or
  node = sendFileCall().getOptionArgument(1, "root")
  or
  exists(DataFlow::Node succ | isRelevantPathNode(succ) | node = succ.getAPredecessor())
}

/**
 * Gets the `/`-joined string values of the arguments `start..` of `call`, if all of them are
 * constant strings.
 */
private string joinedArguments(DataFlow::CallNode call, int start) {
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
 * Holds if `node` evaluates to the path `path`. If `fromDirname` is true, `path` is relative to
 * the folder of the enclosing file, otherwise it is relative to the working directory of the
 * process.
 */
private predicate pathValue(DataFlow::Node node, string path, boolean fromDirname) {
  isRelevantPathNode(node) and
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
    pathValue(node.getAPredecessor(), path, fromDirname)
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
 * Gets the relative path `base/rel`, where either component may be empty.
 */
bindingset[base, rel]
string joinPath(string base, string rel) {
  if base = ""
  then result = rel
  else
    if rel = ""
    then result = base
    else result = base + "/" + rel
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
 * Gets a path, relative to the source root, that `node` may evaluate to. Absolute paths and
 * paths containing `..` are not resolved.
 */
string resolvedPath(DataFlow::Node node) {
  exists(string path, boolean fromDirname, Folder base, string rel |
    pathValue(node, path, fromDirname) and
    rel = normalize(path) and
    not rel.regexpMatch("(.*/)?\\.\\.(/.*)?") and
    (
      fromDirname = true and base = node.getFile().getParentContainer()
      or
      fromDirname = false and base = getAWorkingFolder(node.getFile())
    ) and
    result = joinPath(base.getRelativePath(), rel)
  )
}

/**
 * Gets the path, relative to the source root, of a folder served to the public by `serve`.
 */
string getAServedFolderPath(DataFlow::CallNode serve) {
  serve = staticServeCall() and
  result = resolvedPath(serve.getArgument(0))
}

/**
 * Gets a folder that is served to the public by `serve`.
 */
Folder getAServedFolder(DataFlow::CallNode serve) {
  result.getRelativePath() = getAServedFolderPath(serve)
}

/**
 * Holds if the relative path `path` lies inside the folder served by `serve`, and is served by
 * default, that is, no path component below the served folder starts with a dot (static-file
 * middlewares ignore dotfiles by default).
 */
bindingset[path]
predicate isServedPath(string path, DataFlow::CallNode serve) {
  exists(string folder | folder = getAServedFolderPath(serve) |
    folder = "" and not path.regexpMatch("(.*/)?\\.[^/]*(/.*)?")
    or
    folder != "" and
    path.matches(folder + "/%") and
    not path.suffix(folder.length()).regexpMatch("(.*/)?\\.[^/]*(/.*)?")
  )
}
