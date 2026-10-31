/**
 * @name Information exposure through an error message or stack trace (extended)
 * @description Exception messages and stack traces that propagate to an external user
 *              can reveal implementation details (such as SQL errors, class names and
 *              file paths) that are useful to an attacker for developing a subsequent
 *              exploit.
 * @kind problem
 * @problem.severity error
 * @security-severity 5.4
 * @precision medium
 * @id java/custom/error-message-exposure
 * @tags security
 *       external/cwe/cwe-209
 *       external/cwe/cwe-497
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.InformationLeak
import semmle.code.java.security.StackTraceExposureQuery

/** Holds if `t` is `java.lang.Throwable` or one of its subtypes. */
private predicate isThrowable(RefType t) {
  t.getSourceDeclaration().getASourceSupertype*().hasQualifiedName("java.lang", "Throwable")
}

/**
 * A call to `getMessage()`, `getLocalizedMessage()` or `toString()` on an exception,
 * including overrides of these methods in subclasses of `Throwable`.
 */
private class ExceptionMessageCall extends MethodCall {
  ExceptionMessageCall() {
    this.getMethod().hasName(["getMessage", "getLocalizedMessage", "toString"]) and
    this.getMethod().hasNoParameters() and
    isThrowable(this.getQualifier().getType())
  }
}

/**
 * A `PrintWriter` that wraps a given string writer, as in
 * `t.printStackTrace(new PrintWriter(sw))`.
 */
private predicate printWriterOnStringWriter(Expr printWriter, Variable stringWriterVar) {
  printWriter.getType().(Class).hasQualifiedName("java.io", "PrintWriter") and
  stringWriterVar.getType().(Class).hasQualifiedName("java.io", "StringWriter") and
  (
    printWriter.(ClassInstanceExpr).getAnArgument() = stringWriterVar.getAnAccess() or
    printWriterOnStringWriter(printWriter.(VarAccess).getVariable().getInitializer(),
      stringWriterVar)
  )
}

/**
 * Holds if `stackTraceString` is a `StringWriter.toString()` call that converts the
 * stack trace of `exception` to a string.
 */
private predicate stackTraceString(Expr exception, MethodCall stackTraceString) {
  exists(Expr printWriter, Variable stringWriterVar, MethodCall printStackCall |
    printWriterOnStringWriter(printWriter, stringWriterVar) and
    printStackCall.getMethod().hasName("printStackTrace") and
    isThrowable(printStackCall.getMethod().getDeclaringType()) and
    printStackCall.getAnArgument() = printWriter and
    printStackCall.getQualifier() = exception and
    stackTraceString.getQualifier() = stringWriterVar.getAnAccess() and
    stackTraceString.getMethod() instanceof ToStringMethod
  )
}

/**
 * Holds if `source` is a string containing error information derived from `errorInformation`.
 */
private predicate errorInformationSource(DataFlow::Node source, Expr errorInformation) {
  stackTraceString(errorInformation, source.asExpr())
  or
  source.asExpr() = errorInformation and errorInformation instanceof ExceptionMessageCall
}

/**
 * A value stored as a Spring MVC model attribute. Model attributes are exposed to the
 * rendered view (for example a JSP or Thymeleaf template), so they reach the user.
 */
private class SpringModelAttributeSink extends DataFlow::Node {
  SpringModelAttributeSink() {
    exists(MethodCall ma, Method m, RefType t |
      ma.getMethod() = m and
      t = m.getDeclaringType().getSourceDeclaration().getASourceSupertype*() and
      this.asExpr() = ma.getArgument(m.getNumberOfParameters() - 1) and
      m.getParameterType(m.getNumberOfParameters() - 1) instanceof TypeObject
    |
      t.hasQualifiedName("org.springframework.ui", ["Model", "ModelMap"]) and
      m.hasName("addAttribute")
      or
      t.hasQualifiedName("org.springframework.web.servlet", "ModelAndView") and
      m.hasName("addObject")
    )
  }
}

private module ErrorInformationToExternalFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { errorInformationSource(src, _) }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof InformationLeakSink or
    sink instanceof SpringModelAttributeSink
  }
}

private module ErrorInformationToExternalFlow =
  TaintTracking::Global<ErrorInformationToExternalFlowConfig>;

from Expr externalExpr, Expr errorInformation
where
  printsStackExternally(externalExpr, errorInformation)
  or
  exists(DataFlow::Node source |
    errorInformationSource(source, errorInformation) and
    ErrorInformationToExternalFlow::flow(source, DataFlow::exprNode(externalExpr))
  )
select externalExpr, "$@ can be exposed to an external user.", errorInformation, "Error information"
