/**
 * @name Unbounded outbound fetch or predictable shared temporary file
 * @description Fetching a non-constant URL with `requests` without a timeout lets a slow
 *              or malicious server hold a worker indefinitely, and storing files under a
 *              predictable name in a shared temporary directory such as `/tmp` lets other
 *              local users read, pre-create or replace them.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id py/file-upload-resource-handling
 * @tags security
 *       external/cwe/cwe-377
 *       external/cwe/cwe-400
 */

import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/**
 * A `requests` call (module-level or on a `Session`) that sets no timeout.
 *
 * `requests` has no default timeout, so such a call can block forever.
 */
predicate requestWithoutTimeout(Http::Client::Request req) {
  req.getFramework() = "requests" and
  exists(API::CallNode call | call = req |
    not exists(call.getArgByName("timeout")) and
    // `**kwargs` may carry a timeout.
    not exists(call.getNode().getNode().(Call).getKwargs()) and
    // `Session.request(method, url, params, data, headers, cookies, files, auth, timeout, ...)`
    not exists(call.getArg(8))
  ) and
  // A hard-coded URL is not attacker-influenced.
  not exists(DataFlow::Node url | url = req.getAUrlPart() |
    url.getALocalSource().asExpr() instanceof StringLiteral
  )
}

/** Holds if `s` names a world-writable, shared temporary directory, optionally with a trailing `/`. */
bindingset[s]
predicate isSharedTmpDir(string s) { s.regexpMatch("/(tmp|var/tmp|dev/shm)/?") }

/** Holds if `s` is a path to an entry (file name or name prefix) inside a shared temporary directory. */
bindingset[s]
predicate isSharedTmpEntry(string s) { s.regexpMatch("/(tmp|var/tmp|dev/shm)/[^/].*") }

/** Holds if `pathObj` is used to derive a child path or to search for entries by name. */
predicate derivesChildPath(DataFlow::Node pathObj) {
  exists(DataFlow::AttrRead read |
    read.getAttributeName() in ["glob", "rglob", "joinpath", "with_name"] and
    pathObj.(DataFlow::LocalSourceNode).flowsTo(read.getObject())
  )
  or
  exists(BinaryExpr div |
    div.getOp() instanceof Div and
    pathObj.(DataFlow::LocalSourceNode).flowsTo(DataFlow::exprNode(div.getLeft()))
  )
}

/**
 * Holds if the bare shared temporary directory literal `lit` is combined with a
 * further name component, e.g. `"/tmp/" + name`, `os.path.join("/tmp", name)`,
 * `f"/tmp/{name}"` or `Path("/tmp").glob(pattern)`.
 */
predicate combinedWithName(StringLiteral lit) {
  exists(BinaryExpr b | b.getLeft() = lit and b.getOp() instanceof Add)
  or
  exists(Fstring f | f.getValue(0) = lit and exists(f.getValue(1)))
  or
  exists(API::CallNode join |
    join = API::moduleImport(["os", "posixpath"]).getMember("path").getMember("join").getACall() and
    join.getArg(0).asExpr() = lit and
    exists(join.getArg(1))
  )
  or
  exists(API::CallNode path |
    path =
      API::moduleImport("pathlib")
          .getMember(["Path", "PosixPath", "PurePath", "PurePosixPath"])
          .getACall() and
    path.getArg(0).asExpr() = lit
  |
    exists(path.getArg(1)) or derivesChildPath(path)
  )
}

/** A string literal that yields a predictable path inside a shared temporary directory. */
class PredictableSharedTmpPath extends StringLiteral {
  PredictableSharedTmpPath() {
    isSharedTmpEntry(this.getText())
    or
    isSharedTmpDir(this.getText()) and combinedWithName(this)
  }
}

module PredictableTmpPathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof PredictableSharedTmpPath }

  predicate isSink(DataFlow::Node sink) { sink = any(FileSystemAccess a).getAPathArgument() }
}

module PredictableTmpPathFlow = TaintTracking::Global<PredictableTmpPathConfig>;

from DataFlow::Node alert, string message, DataFlow::Node related, string relatedLabel
where
  requestWithoutTimeout(alert) and
  related = alert.(Http::Client::Request).getAUrlPart() and
  message =
    "Outbound request to a non-constant $@ has no timeout, so a slow or unbounded response can exhaust server resources." and
  relatedLabel = "URL"
  or
  exists(FileSystemAccess access, DataFlow::Node sink |
    alert = access and
    sink = access.getAPathArgument() and
    // Only report the call that receives the path, not e.g. later `write` calls on the opened file.
    sink.asExpr().getParentNode*() = access.asExpr() and
    related =
      min(DataFlow::Node src |
        PredictableTmpPathFlow::flow(src, sink)
      |
        src order by src.getLocation().getStartLine(), src.getLocation().getStartColumn()
      ) and
    message =
      "File system access uses a predictable $@ in a shared temporary directory, which other local users can read, pre-create or replace." and
    relatedLabel = "path"
  )
select alert, message, related, relatedLabel
