/**
 * @name Uncontrolled request data in resource handling
 * @description Using request data to build a database connection string, set a search-path
 *              environment variable, bound a loop, size an allocation, or name an uploaded
 *              file saved under the web root can lead to unauthorized access, code execution,
 *              or denial of service.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision medium
 * @id cs/file-upload-resource-handling
 * @tags security
 *       external/cwe/cwe-015
 *       external/cwe/cwe-400
 *       external/cwe/cwe-427
 *       external/cwe/cwe-434
 *       external/cwe/cwe-789
 */

import csharp
import semmle.code.csharp.controlflow.Guards
import semmle.code.csharp.security.dataflow.flowsources.FlowSources

/** A `System.Web` type that represents an uploaded file. */
class SystemWebUploadedFileType extends RefType {
  SystemWebUploadedFileType() {
    this.hasFullyQualifiedName("System.Web.UI.WebControls", "FileUpload") or
    this.hasFullyQualifiedName("System.Web",
      ["HttpPostedFile", "HttpPostedFileBase", "HttpPostedFileWrapper"])
  }
}

/** An access to the client-supplied `FileName` of an uploaded file. */
class UploadedFileNameSource extends DataFlow::ExprNode {
  UploadedFileNameSource() {
    exists(Property p |
      p.hasName("FileName") and
      (
        p.getDeclaringType().getABaseType*() instanceof SystemWebUploadedFileType or
        p.getDeclaringType()
            .getABaseType*()
            .hasFullyQualifiedName("Microsoft.AspNetCore.Http", "IFormFile")
      ) and
      this.getExpr() = p.getAnAccess()
    )
  }
}

/** A type representing a database connection. */
class DbConnectionType extends RefType {
  DbConnectionType() {
    this.getABaseType*().hasFullyQualifiedName("System.Data", "IDbConnection") or
    this.getABaseType*().hasFullyQualifiedName("System.Data.Common", "DbConnection") or
    this.getABaseType*()
        .hasFullyQualifiedName(["System.Data.SqlClient", "Microsoft.Data.SqlClient"],
          "SqlConnection")
  }
}

/** Holds if `e` is the length or count of an existing collection or string. */
predicate isSizeOfExistingData(Expr e) {
  e.(PropertyAccess).getTarget().hasName(["Length", "LongLength", "Count"])
}

/** An expression of integral type that is not merely the size of existing data. */
class SizeExpr extends Expr {
  SizeExpr() {
    this.getType() instanceof IntegralType and
    not isSizeOfExistingData(this)
  }
}

/** Gets a web-root path expression, such as `Server.MapPath(...)` or `env.WebRootPath`. */
Expr getAWebRootPath() {
  exists(MethodCall mc | mc = result |
    mc.getTarget().hasName("MapPath") and
    mc.getTarget()
        .getDeclaringType()
        .getABaseType*()
        .hasFullyQualifiedName("System.Web",
          ["HttpServerUtility", "HttpServerUtilityBase", "HttpServerUtilityWrapper"])
    or
    mc.getTarget().hasFullyQualifiedName("System.Web.Hosting", "HostingEnvironment", "MapPath")
  )
  or
  exists(PropertyAccess pa | pa = result |
    pa.getTarget().hasName("WebRootPath") and
    pa.getTarget()
        .getDeclaringType()
        .hasFullyQualifiedName("Microsoft.AspNetCore.Hosting",
          ["IWebHostEnvironment", "IHostingEnvironment"])
  )
  or
  result.(StringLiteral).getValue().regexpMatch("(?i).*\\bwwwroot\\b.*")
}

/** Holds if `c` copies an ASP.NET Core `IFormFile` to a stream. */
predicate copiesFormFile(Callable c) {
  exists(MethodCall mc |
    mc.getEnclosingCallable() = c and
    mc.getTarget().hasName(["CopyTo", "CopyToAsync"]) and
    mc.getTarget()
        .getDeclaringType()
        .getABaseType*()
        .hasFullyQualifiedName("Microsoft.AspNetCore.Http", "IFormFile")
  )
}

/** Gets the path argument of a call that saves uploaded content to the file system. */
Expr getAnUploadSavePath() {
  exists(MethodCall mc | result = mc.getArgument(0) |
    mc.getTarget().hasName("SaveAs") and
    mc.getTarget().getDeclaringType().getABaseType*() instanceof SystemWebUploadedFileType
  )
  or
  copiesFormFile(result.getEnclosingCallable()) and
  (
    exists(ObjectCreation oc | result = oc.getArgumentForName("path") |
      oc.getObjectType().hasFullyQualifiedName("System.IO", "FileStream")
    )
    or
    exists(MethodCall mc | result = mc.getArgumentForName("path") |
      mc.getTarget().hasFullyQualifiedName("System.IO", "File", ["Create", "OpenWrite", "Open"])
    )
  )
}

/** Holds if `cond` checks the extension of a file name. */
predicate isExtensionCheck(Expr cond) {
  exists(MethodCall ext |
    ext.getTarget().hasFullyQualifiedName("System.IO", "Path", "GetExtension") and
    TaintTracking::localExprTaint(ext, cond.getAChildExpr*())
  )
  or
  exists(MethodCall endsWith |
    endsWith.getTarget().hasFullyQualifiedName("System", "String", "EndsWith") and
    endsWith = cond.getAChildExpr*()
  )
}

/**
 * Holds if `e` is only reached after a check on the extension of a file name, either
 * because it is nested in a branch of such a check or because the check controls it.
 */
predicate isGuardedByExtensionCheck(Expr e) {
  exists(IfStmt ifs |
    isExtensionCheck(ifs.getCondition()) and
    ifs.getAChildStmt+() = e.getEnclosingStmt()
  )
  or
  exists(Guard g |
    isExtensionCheck(g) and
    g.getEnclosingCallable() = e.getEnclosingCallable() and
    g.controlsBasicBlock(e.getControlFlowNode().getBasicBlock(), _)
  )
}

/** A sink for request data used in resource handling. */
class ResourceHandlingSink extends DataFlow::ExprNode {
  string kind;

  ResourceHandlingSink() {
    // CWE-15: request data in a database connection string or catalog selection.
    kind = "connection-string" and
    (
      exists(ObjectCreation oc |
        oc.getObjectType() instanceof DbConnectionType and
        this.getExpr() = oc.getArgumentForName("connectionString")
      )
      or
      exists(AssignExpr a, PropertyAccess pa |
        pa = a.getLValue() and
        pa.getTarget().hasName("ConnectionString") and
        pa.getTarget().getDeclaringType() instanceof DbConnectionType and
        this.getExpr() = a.getRValue()
      )
      or
      exists(MethodCall mc |
        mc.getTarget().hasName("ChangeDatabase") and
        mc.getTarget().getDeclaringType() instanceof DbConnectionType and
        this.getExpr() = mc.getArgument(0)
      )
    )
    or
    // CWE-427: request data assigned to a search-path environment variable.
    kind = "search-path" and
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("System", "Environment", "SetEnvironmentVariable") and
      mc.getArgument(0).getValue().toUpperCase() =
        ["PATH", "PATHEXT", "LD_LIBRARY_PATH", "LD_PRELOAD", "DYLD_LIBRARY_PATH", "PYTHONPATH"] and
      this.getExpr() = mc.getArgument(1)
    )
    or
    // CWE-400 / CWE-606: request data used as the bound of a loop.
    kind = "loop-bound" and
    exists(LoopStmt loop, RelationalOperation cmp |
      cmp.getParent*() = loop.getCondition() and
      this.getExpr() = cmp.getGreaterOperand() and
      this.getExpr() instanceof SizeExpr
    )
    or
    // CWE-789: request data used as an allocation size or collection capacity.
    kind = "allocation-size" and
    this.getExpr() instanceof SizeExpr and
    (
      this.getExpr() = any(ArrayCreation ac).getALengthArgument()
      or
      this.getExpr() = any(ObjectCreation oc).getArgumentForName("capacity")
    )
    or
    // CWE-434: client-controlled file name used to save an upload under the web root.
    kind = "upload" and
    this.getExpr() = getAnUploadSavePath() and
    TaintTracking::localExprTaint(getAWebRootPath(), this.getExpr()) and
    not isGuardedByExtensionCheck(this.getExpr())
  }

  /** Gets the kind of this sink. */
  string getKind() { result = kind }

  /** Gets a description of the operation performed by this sink. */
  string getDescription() {
    kind = "connection-string" and result = "a database connection setting"
    or
    kind = "search-path" and result = "a search-path environment variable"
    or
    kind = "loop-bound" and result = "an unbounded loop limit"
    or
    kind = "allocation-size" and result = "an unbounded allocation size"
    or
    kind = "upload" and
    result = "the name of an uploaded file saved under the web root without an extension check"
  }
}

/** Holds if `g` checks `e` against a constant upper bound when evaluating to `v`. */
predicate upperBoundCheck(Guard g, Expr e, GuardValue v) {
  exists(RelationalOperation cmp | cmp = g |
    e = cmp.getLesserOperand() and
    exists(cmp.getGreaterOperand().getValue()) and
    v.asBooleanValue() = true
    or
    e = cmp.getGreaterOperand() and
    exists(cmp.getLesserOperand().getValue()) and
    v.asBooleanValue() = false
  )
}

module FileUploadResourceHandlingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof ActiveThreatModelSource or
    source instanceof UploadedFileNameSource
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof ResourceHandlingSink }

  predicate isBarrier(DataFlow::Node node) {
    node = DataFlow::BarrierGuard<upperBoundCheck/3>::getABarrierNode()
    or
    exists(MethodCall mc | mc = node.asExpr() |
      mc.getTarget().hasFullyQualifiedName("System", "Math", ["Min", "Clamp"])
      or
      mc.getTarget()
          .hasFullyQualifiedName("System.IO", "Path",
            ["ChangeExtension", "GetFileNameWithoutExtension", "GetRandomFileName"])
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module FileUploadResourceHandlingFlow = TaintTracking::Global<FileUploadResourceHandlingConfig>;

import FileUploadResourceHandlingFlow::PathGraph

from FileUploadResourceHandlingFlow::PathNode source, FileUploadResourceHandlingFlow::PathNode sink
where FileUploadResourceHandlingFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This $@ is used as " + sink.getNode().(ResourceHandlingSink).getDescription() + ".",
  source.getNode(), "user-provided value"
