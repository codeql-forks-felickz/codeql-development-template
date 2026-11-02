/**
 * @name Unbounded servlet request dispatch loop
 * @description A servlet that unconditionally forwards or includes a request to a path handled by
 *              itself (directly or through other servlets) dispatches the request recursively
 *              without a termination condition, exhausting request threads and the stack.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision high
 * @id java/servlet-dispatch-loop
 * @tags security
 *       external/cwe/cwe-835
 *       external/cwe/cwe-674
 *       external/cwe/cwe-400
 */

import java
import semmle.code.java.controlflow.Guards
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.frameworks.Servlets
import semmle.code.xml.WebXML

/** A request handling method of a servlet. */
class ServletHandlerMethod extends Method {
  ServletHandlerMethod() {
    this.getDeclaringType() instanceof ServletClass and
    this.hasName([
        "service", "doGet", "doPost", "doPut", "doDelete", "doHead", "doOptions", "doTrace"
      ]) and
    exists(this.getBody())
  }
}

/** Gets a URL pattern that `servlet` is mapped to, using `@WebServlet` or `web.xml`. */
predicate servletUrlPattern(Class servlet, string pattern, File mappingFile, boolean isXml) {
  exists(Annotation a |
    a = servlet.getAnAnnotation() and
    a.getType().hasQualifiedName(["javax", "jakarta"] + ".servlet.annotation", "WebServlet") and
    pattern = a.getAStringArrayValue(["value", "urlPatterns"]) and
    mappingFile = servlet.getFile() and
    isXml = false
  )
  or
  exists(WebServlet decl, WebXmlElement mapping, string name |
    servlet = decl.getAChild().(WebServletClass).getClass() and
    name = decl.getAChild("servlet-name").(WebXmlElement).getValue() and
    mapping.getName() = "servlet-mapping" and
    decl.getFile() = mapping.getFile() and
    mapping.getAChild("servlet-name").(WebXmlElement).getValue() = name and
    pattern = mapping.getAChild("url-pattern").(WebXmlElement).getValue() and
    mappingFile = decl.getFile() and
    isXml = true
  )
}

/** Holds if `first` has higher servlet mapping priority than `second`. */
bindingset[first, second]
predicate patternOutranks(string first, string second) {
  (not first.matches("%/*") and not first.matches("*.%")) and
  (second.matches("%/*") or second.matches("*.%"))
  or
  first.matches("%/*") and second.matches("*.%")
  or
  first.matches("%/*") and second.matches("%/*") and first.length() > second.length()
}

/** Gets the scope shared by annotation mappings or the scope of one web.xml descriptor. */
bindingset[mappingFile, isXml]
predicate servletMappingScope(File mappingFile, boolean isXml, string scope) {
  isXml = false and scope = "annotations"
  or
  isXml = true and scope = "web.xml:" + mappingFile.getRelativePath()
}

/** Holds if the context-relative `path` (without query string) matches the URL `pattern`. */
bindingset[path, pattern]
predicate pathMatchesPattern(string path, string pattern) {
  path = pattern
  or
  exists(string prefix | pattern = prefix + "/*" |
    path = prefix or path.matches(prefix + "/%") or prefix = ""
  )
  or
  exists(string ext | pattern = "*." + ext and not ext.matches("%/%") | path.matches("%." + ext))
}

/**
 * Holds if `dispatch` is a call to `RequestDispatcher.forward` or `include` that is executed on
 * every invocation of the handler method that contains it, and dispatches to the constant
 * context-relative `path`.
 */
predicate unconditionalDispatch(ServletHandlerMethod handler, MethodCall dispatch, string path) {
  dispatch.getEnclosingCallable() = handler and
  dispatch.getMethod() instanceof RequestDispatchMethod and
  exists(MethodCall getDispatcher, string target |
    getDispatcher.getMethod() instanceof GetRequestDispatcherMethod and
    target = getDispatcher.getArgument(0).(CompileTimeConstantExpr).getStringValue() and
    target.charAt(0) = "/" and
    (if target.matches("%?%") then path = target.prefix(target.indexOf("?")) else path = target) and
    DataFlow::localExprFlow(getDispatcher, dispatch.getQualifier())
  ) and
  // The dispatch is not guarded by a condition (an `if`, loop, `switch` case or early return)
  // and is not only executed when an exception is caught.
  not exists(Guard g |
    g.getEnclosingCallable() = handler and
    g.controls(dispatch.getControlFlowNode().getBasicBlock(), _)
  ) and
  not dispatch.getEnclosingStmt().getEnclosingStmt*() = any(CatchClause c).getBlock()
}

/**
 * Holds if `handler` unconditionally dispatches requests to `path` at `dispatch`, and `path` is
 * handled by servlet `target`.
 */
predicate dispatchEdge(
  ServletHandlerMethod handler, MethodCall dispatch, string path, Class target, string mappingScope
) {
  unconditionalDispatch(handler, dispatch, path) and
  exists(string pattern, File targetFile, boolean targetIsXml |
    servletUrlPattern(target, pattern, targetFile, targetIsXml) and
    servletMappingScope(targetFile, targetIsXml, mappingScope) and
    pathMatchesPattern(path, pattern) and
    not exists(Class other, string otherPattern, File otherFile, boolean otherIsXml |
      servletUrlPattern(other, otherPattern, otherFile, otherIsXml) and
      servletMappingScope(otherFile, otherIsXml, mappingScope) and
      pathMatchesPattern(path, otherPattern) and
      patternOutranks(otherPattern, pattern)
    )
  ) and
  exists(string sourcePattern, File sourceFile, boolean sourceIsXml |
    servletUrlPattern(handler.getDeclaringType(), sourcePattern, sourceFile, sourceIsXml) and
    servletMappingScope(sourceFile, sourceIsXml, mappingScope)
  )
}

/** Holds if servlet `source` unconditionally dispatches requests to servlet `target`. */
predicate servletDispatches(Class source, Class target, string mappingScope) {
  exists(ServletHandlerMethod handler |
    dispatchEdge(handler, _, _, target, mappingScope) and
    source = handler.getDeclaringType()
  )
}

/** Holds if `source` dispatches to `target` within one annotation set or web.xml descriptor. */
predicate servletDispatchesInScope(Class source, Class target, string mappingScope) {
  servletDispatches(source, target, mappingScope)
  or
  exists(Class intermediate |
    servletDispatches(source, intermediate, mappingScope) and
    servletDispatchesInScope(intermediate, target, mappingScope)
  )
}

from
  ServletHandlerMethod handler, MethodCall dispatch, string path, Class target, string suffix,
  string mappingScope
where
  dispatchEdge(handler, dispatch, path, target, mappingScope) and
  servletDispatchesInScope(target, handler.getDeclaringType(), mappingScope) and
  (
    if target = handler.getDeclaringType()
    then suffix = " (this servlet)"
    else suffix = ", which dispatches back to this servlet"
  )
select dispatch,
  "This request is unconditionally dispatched to '" + path + "', which is handled by $@" + suffix +
    ", so it is dispatched recursively without a termination condition.", target, target.getName()
