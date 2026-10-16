/**
 * @name Unrestricted upload of file with dangerous type to a web-accessible directory
 * @description Storing an uploaded file in a web-accessible directory under a file name or
 *              extension chosen by the client, without validating it against an allowlist,
 *              lets an attacker upload active or server-executable content such as
 *              `.html` or `.jsp` files.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/file-upload-resource-handling
 * @tags security
 *       external/cwe/cwe-434
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.controlflow.Guards

/** A type representing a file received in a multipart upload request. */
class UploadedFileType extends RefType {
  UploadedFileType() {
    this.getASourceSupertype*()
        .hasQualifiedName("org.springframework.web.multipart", "MultipartFile")
    or
    this.getASourceSupertype*()
        .hasQualifiedName(["javax.servlet.http", "jakarta.servlet.http"], "Part")
  }
}

/** A call that returns the file name supplied by the client for an uploaded file. */
class ClientFileNameCall extends MethodCall {
  ClientFileNameCall() {
    this.getMethod().getDeclaringType() instanceof UploadedFileType and
    this.getMethod().hasName(["getOriginalFilename", "getSubmittedFileName"])
  }
}

/** A call that reads the content of an uploaded file. */
class UploadedContentCall extends MethodCall {
  UploadedContentCall() {
    this.getMethod().getDeclaringType() instanceof UploadedFileType and
    this.getMethod().hasName(["getInputStream", "getBytes"])
  }
}

/**
 * Gets the expression that determines the destination of a write that stores the
 * content of an uploaded file.
 */
Expr uploadDestination() {
  // `MultipartFile.transferTo(File|Path)`, `Part.write(String)`
  exists(MethodCall mc |
    mc.getMethod().getDeclaringType() instanceof UploadedFileType and
    mc.getMethod().hasName(["transferTo", "write"]) and
    result = mc.getArgument(0)
  )
  or
  // `Files.copy(upload.getInputStream(), dest, ...)`, `Files.write(dest, upload.getBytes(), ...)`
  exists(MethodCall mc, int content, int dest |
    mc.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    (
      mc.getMethod().hasName("copy") and content = 0 and dest = 1
      or
      mc.getMethod().hasName("write") and content = 1 and dest = 0
    ) and
    DataFlow::localExprFlow(any(UploadedContentCall c), mc.getArgument(content)) and
    result = mc.getArgument(dest)
  )
}

/**
 * Holds if the resource name `s` refers to a classpath location that is served as static
 * web content (for example Spring Boot's `static`, `public`, `resources` and
 * `META-INF/resources` locations).
 */
bindingset[s]
private predicate isWebRootPath(string s) {
  s.regexpMatch("(?i)/?(META-INF/)?(static|public|resources)(/.*)?")
}

/** An expression that evaluates to a location inside a web-accessible directory. */
class WebRootExpr extends Expr {
  WebRootExpr() {
    // `ServletContext.getRealPath(...)` resolves a path inside the deployed web application.
    exists(MethodCall mc | mc = this |
      mc.getMethod()
          .getDeclaringType()
          .getASourceSupertype*()
          .hasQualifiedName(["javax.servlet", "jakarta.servlet"], "ServletContext") and
      mc.getMethod().hasName("getRealPath")
    )
    or
    // `ClassLoader.getResource("static")`, `Class.getResource("/public/...")`
    exists(MethodCall mc | mc = this |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.lang", ["ClassLoader", "Class"]) and
      mc.getMethod().hasName("getResource") and
      isWebRootPath(mc.getArgument(0).(CompileTimeConstantExpr).getStringValue())
    )
    or
    // A literal path such as `"src/main/resources/static/uploads"`.
    this.(StringLiteral)
        .getValue()
        .regexpMatch("(?i)(.*/)?src/main/(webapp|resources/(static|public))(/.*)?")
  }
}

/**
 * Holds if `g` validates `e` against an allowlist when `g` evaluates to `branch`,
 * for example `name.endsWith(".png")`, `ALLOWED.contains(ext)` or
 * `PATTERN.matcher(name).matches()`.
 */
private predicate allowlistGuard(Guard g, Expr e, boolean branch) {
  branch = true and
  exists(MethodCall mc | mc = g |
    // `name.endsWith(".png")`, `ext.equals(".png")`, `name.matches(regex)`
    mc.getMethod().getDeclaringType() instanceof TypeString and
    mc.getMethod().hasName(["endsWith", "equals", "equalsIgnoreCase", "matches"]) and
    e = mc.getQualifier()
    or
    // `".png".equalsIgnoreCase(ext)`
    mc.getMethod().getDeclaringType() instanceof TypeString and
    mc.getMethod().hasName(["equals", "equalsIgnoreCase"]) and
    e = mc.getArgument(0)
    or
    // `ALLOWED_EXTENSIONS.contains(ext)`
    mc.getMethod()
        .getDeclaringType()
        .getSourceDeclaration()
        .getASourceSupertype*()
        .hasQualifiedName("java.util", "Collection") and
    mc.getMethod().hasName("contains") and
    e = mc.getArgument(0)
    or
    // `PATTERN.matcher(name).matches()`
    mc.getMethod().getDeclaringType().hasQualifiedName("java.util.regex", "Matcher") and
    mc.getMethod().hasName("matches") and
    exists(MethodCall matcher |
      matcher = mc.getQualifier() and
      matcher.getMethod().getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
      matcher.getMethod().hasName("matcher") and
      e = matcher.getArgument(0)
    )
    or
    // `Pattern.matches(regex, name)`
    mc.getMethod().getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
    mc.getMethod().hasName("matches") and
    e = mc.getArgument(1)
  )
}

/** Tracks values that locate a web-accessible directory to upload destinations. */
module WebRootConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof WebRootExpr }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() = uploadDestination() }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    // The upload directory is commonly computed once and stored in a field.
    exists(Field f |
      n1.asExpr() = f.getAnAssignedValue() and
      n2.asExpr().(FieldRead).getField() = f
    )
  }
}

/** Taint flow of web-accessible directory locations to upload destinations. */
module WebRootFlow = TaintTracking::Global<WebRootConfig>;

/** Tracks client-supplied upload file names to upload destinations in a web-accessible directory. */
module UploadFileNameConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof ClientFileNameCall }

  predicate isSink(DataFlow::Node sink) { WebRootFlow::flowTo(sink) }

  predicate isBarrier(DataFlow::Node node) {
    node.getType() instanceof PrimitiveType or
    node.getType() instanceof BoxedType or
    node = DataFlow::BarrierGuard<allowlistGuard/3>::getABarrierNode()
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    // `new File(dir, name)`
    exists(ConstructorCall cc |
      cc.getConstructedType() instanceof TypeFile and
      n1.asExpr() = cc.getArgument(1) and
      n2.asExpr() = cc
    )
  }
}

/** Taint flow of client-supplied upload file names to upload destinations in a web-accessible directory. */
module UploadFileNameFlow = TaintTracking::Global<UploadFileNameConfig>;

import UploadFileNameFlow::PathGraph

from UploadFileNameFlow::PathNode source, UploadFileNameFlow::PathNode sink
where UploadFileNameFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Uploaded file is stored in a web-accessible directory under a name and extension derived from $@, which is not validated against an allowlist.",
  source.getNode(), "the client-supplied file name"
