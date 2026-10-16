/**
 * Provides a taint step that models calls through function-typed struct fields.
 *
 * The standard Go data-flow library only resolves the target of a call through a
 * function value when that value reaches the callee expression by local flow (or a
 * jump step). A function or method value that is stored in a struct field (for
 * example in a struct literal that is appended to a global registry) and later
 * invoked as `x.Field(args)` in another function therefore has no resolved callee,
 * and taint passed as an argument is lost.
 *
 * This step connects argument `i` of such an unresolved call to parameter `i` of
 * every function value that is written to the same field anywhere in the program.
 */

import go

/**
 * Holds if `fn` is a function value (a reference to a named function, a method
 * value, or a function literal) whose `i`th parameter is `p`.
 */
private predicate functionValueParameter(DataFlow::Node fn, int i, DataFlow::ParameterNode p) {
  exists(Function f | fn = f.getARead() and p = DataFlow::parameterNode(f.getParameter(i)))
  or
  p = fn.(DataFlow::FuncLitNode).getParameter(i)
}

/**
 * Holds if `rhs` initializes field `f` in an element literal whose type is elided
 * and implied to be a pointer to a struct, as in `[]*T{{F: rhs}}`.
 *
 * Such literals have pointer type and so are not `StructLit`s, which means that no
 * field-write instruction is generated for them.
 */
private predicate initializesFieldOfElidedPointerLit(DataFlow::Node rhs, Field f) {
  exists(CompositeLit lit, StructType st, int i, Expr elt |
    st = lit.getType().getUnderlyingType().(PointerType).getBaseType().getUnderlyingType() and
    elt = lit.getElement(i)
  |
    f = st.getField(elt.(KeyValueExpr).getKey().(Ident).getName()) and
    rhs.asExpr() = elt.(KeyValueExpr).getValue()
    or
    not elt instanceof KeyValueExpr and
    exists(string name | st.hasOwnField(i, name, _, _) | f = st.getField(name)) and
    rhs.asExpr() = elt
  )
}

/** Holds if the function value `fn` may be stored in the function-typed field `f`. */
private predicate storedInField(DataFlow::Node fn, Field f) {
  f.getType().getUnderlyingType() instanceof SignatureType and
  exists(DataFlow::Node rhs |
    any(Write w).writesField(_, f, rhs) or initializesFieldOfElidedPointerLit(rhs, f)
  |
    DataFlow::localFlow(fn, rhs)
  )
}

/**
 * Holds if `call` invokes the function stored in field `f`, and the standard library
 * could not resolve any callee for it.
 */
private predicate unresolvedFieldCall(DataFlow::CallNode call, Field f) {
  call.getCalleeNode().(DataFlow::FieldReadNode).getField() = f and
  not exists(call.getACalleeIncludingExternals())
}

/**
 * A taint step from an argument of a call through a function-typed field to the
 * corresponding parameter of a function value stored in that field.
 */
class FunctionFieldCallTaintStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(DataFlow::CallNode call, Field f, DataFlow::Node fn, int i |
      unresolvedFieldCall(call, f) and
      storedInField(fn, f) and
      functionValueParameter(fn, i, succ) and
      pred = call.getArgument(i)
    )
  }
}
