/**
 * @name Loading code from another package while ignoring security
 * @description Calling `Context.createPackageContext` with both `CONTEXT_INCLUDE_CODE` and
 *              `CONTEXT_IGNORE_SECURITY` loads code from another installed package without
 *              verifying who signed it, so any application using a matching package name can
 *              run code inside this application.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id java/android/unsafe-package-context-code-loading
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-749
 *       external/cwe/cwe-829
 */

import java
import semmle.code.java.dataflow.DataFlow

/** The value of `android.content.Context.CONTEXT_INCLUDE_CODE`. */
int contextIncludeCode() { result = 1 }

/** The value of `android.content.Context.CONTEXT_IGNORE_SECURITY`. */
int contextIgnoreSecurity() { result = 2 }

/** The method `android.content.Context.createPackageContext` or an override of it. */
class CreatePackageContextMethod extends Method {
  CreatePackageContextMethod() {
    this.getSourceDeclaration()
        .overridesOrInstantiates*(any(Method m |
            m.hasQualifiedName("android.content", "Context", "createPackageContext")
          ))
  }
}

/** Holds if `flags` is a compile-time constant that sets both unsafe flags. */
predicate isUnsafeFlags(CompileTimeConstantExpr flags) {
  exists(int unsafe | unsafe = contextIncludeCode().bitOr(contextIgnoreSecurity()) |
    flags.getIntValue().bitAnd(unsafe) = unsafe
  )
}

from MethodCall call, CompileTimeConstantExpr flags
where
  call.getMethod() instanceof CreatePackageContextMethod and
  isUnsafeFlags(flags) and
  DataFlow::localExprFlow(flags, call.getArgument(1))
select call,
  "Code from another package is loaded with CONTEXT_INCLUDE_CODE and CONTEXT_IGNORE_SECURITY, skipping signature verification."
