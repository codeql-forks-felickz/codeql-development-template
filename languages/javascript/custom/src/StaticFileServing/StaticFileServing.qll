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
 * Gets a call to [`serve-index`](https://npmjs.com/package/serve-index), which creates a
 * middleware that serves a directory listing of the folder given as its first argument.
 */
DataFlow::CallNode directoryListingCall() {
  result = DataFlow::moduleImport("serve-index").getACall()
}

/**
 * Gets a call to `res.sendFile` or `res.download` on an HTTP response object, including
 * responses whose type is only known from a TypeScript annotation (for example handlers
 * returned from factory functions).
 */
DataFlow::MethodCallNode fileResponseCall() {
  result.getMethodName() = ["sendFile", "sendfile", "download"] and
  (
    result.getReceiver() instanceof Http::ResponseNode
    or
    exists(Parameter p |
      result.getReceiver().getALocalSource() = DataFlow::parameterNode(p) and
      p.getTypeAnnotation().hasUnderlyingType("express", "Response")
    )
  )
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
 * Gets a call to `path.join` or `path.resolve` (also imported as `node:path`).
 */
DataFlow::CallNode pathJoinCall() {
  result = DataFlow::moduleMember(["path", "node:path"], ["join", "resolve"]).getACall()
}

/**
 * Holds if `node` is a reference to `__dirname`.
 */
predicate isDirname(DataFlow::Node node) {
  exists(ModuleScope ms | node.asExpr() = ms.getVariable("__dirname").getAnAccess())
  or
  // ES modules and TypeScript files compiled to CommonJS
  node.asExpr().(GlobalVarAccess).getName() = "__dirname"
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
  node = directoryListingCall().getArgument(0)
  or
  node = fileResponseCall().getOptionArgument(1, "root")
  or
  exists(DataFlow::Node succ | isRelevantPathNode(succ) | node = succ.getAPredecessor())
}

/**
 * Gets the `/`-joined string values of the arguments `start..` of `call`, if all of them are
 * constant strings.
 */
private string joinedArguments(DataFlow::CallNode call, int start) {
  result = joinedArguments(call, start, call.getNumArgument() - 1)
}

/**
 * Gets the `/`-joined string values of the arguments `start..end` of `call`, if all of them are
 * constant strings.
 */
private string joinedArguments(DataFlow::CallNode call, int start, int end) {
  start in [0, 1] and
  end in [start .. call.getNumArgument() - 1] and
  forall(int i | i in [start .. end] | exists(call.getArgument(i).getStringValue())) and
  result =
    concat(int i, string s |
      i in [start .. end] and s = call.getArgument(i).getStringValue()
    |
      s, "/" order by i
    )
}

/**
 * Holds if `join` is a call `path.join(..., file)` or `path.resolve(..., file)` whose last
 * argument is not a constant, and whose other arguments evaluate to the folder `path`
 * (see `pathValue`).
 */
private predicate folderPrefixValue(DataFlow::CallNode join, string path, boolean fromDirname) {
  join = pathJoinCall() and
  join.getNumArgument() >= 2 and
  not exists(join.getLastArgument().getStringValue()) and
  (
    isDirname(join.getArgument(0)) and
    join.getNumArgument() >= 3 and
    path = joinedArguments(join, 1, join.getNumArgument() - 2) and
    fromDirname = true
    or
    not isDirname(join.getArgument(0)) and
    path = joinedArguments(join, 0, join.getNumArgument() - 2) and
    not path.matches("/%") and
    fromDirname = false
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
      join = pathJoinCall()
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
 * Holds if `node` evaluates to the path `path`, written `rel` after normalization. If
 * `fromDirname` is true, `rel` is relative to the folder of the enclosing file, otherwise it is
 * relative to the working directory of the process. Paths containing `..` are excluded.
 */
private predicate relativePath(DataFlow::Node node, string rel, boolean fromDirname) {
  exists(string path | pathValue(node, path, fromDirname) |
    rel = normalize(path) and
    not rel.regexpMatch("(.*/)?\\.\\.(/.*)?")
  )
}

/**
 * Gets a path, relative to the source root, that `node` may evaluate to. Absolute paths and
 * paths containing `..` are not resolved.
 */
string resolvedPath(DataFlow::Node node) {
  exists(boolean fromDirname, Folder base, string rel |
    relativePath(node, rel, fromDirname) and
    (
      fromDirname = true and base = node.getFile().getParentContainer()
      or
      fromDirname = false and base = getAWorkingFolder(node.getFile())
    ) and
    result = joinPath(base.getRelativePath(), rel)
  )
}

/**
 * Holds if `exposer` makes the contents of the folder written as `rel` available over HTTP,
 * where `kind` describes how:
 *
 * - `"static"`: a static-file middleware serving every file in the folder,
 * - `"listing"`: a `serve-index` middleware listing the files in the folder,
 * - `"download"`: a `res.sendFile` or `res.download` call that sends a non-constant file name
 *   from inside the folder.
 *
 * `rel` is normalized, and relative to the folder of `exposer` if `fromDirname` is true,
 * otherwise to the working directory of the process.
 */
predicate exposesFolder(DataFlow::Node exposer, string kind, string rel, boolean fromDirname) {
  exposer = staticServeCall() and
  kind = "static" and
  relativePath(exposer.(DataFlow::CallNode).getArgument(0), rel, fromDirname)
  or
  exposer = directoryListingCall() and
  kind = "listing" and
  relativePath(exposer.(DataFlow::CallNode).getArgument(0), rel, fromDirname)
  or
  exists(DataFlow::MethodCallNode call | call = fileResponseCall() and exposer = call |
    kind = "download" and
    (
      not exists(call.getOptionArgument(1, "root")) and
      exists(string path |
        folderPrefixValue(call.getArgument(0).getALocalSource(), path, fromDirname) and
        rel = normalize(path) and
        not rel.regexpMatch("(.*/)?\\.\\.(/.*)?")
      )
      or
      not exists(call.getArgument(0).getStringValue()) and
      relativePath(call.getOptionArgument(1, "root"), rel, fromDirname)
    )
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
