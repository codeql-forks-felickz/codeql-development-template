/**
 * Provides a taint step that models calls through function-typed struct fields.
 *
 * The Go call graph only resolves the callee of a call such as `s.Handler(x)` when the function
 * value reaches the callee expression by local flow. When the function is stored in a struct
 * field in one place (for example `Sink{Handler: execHandler}`) and the field is read and called
 * elsewhere, the call has no callee, so data passed as an argument never reaches the parameters
 * of the function. This is a common pattern for registering framework-agnostic route handlers.
 */

import go

/**
 * Gets the struct type initialized by the composite literal `lit`. This includes the elements of
 * a `[]*T{...}` or `map[K]*T{...}` literal, which elide `&T` and have type `*T` rather than `T`, so
 * they are not `StructLit`s and their field initializations are not modeled as field writes.
 */
private StructType initializedStructType(CompositeLit lit) {
  result = lit.getType().getUnderlyingType()
  or
  result = lit.getType().getUnderlyingType().(PointerType).getBaseType().getUnderlyingType()
}

/** Holds if `rhs` is written to the field `f`. */
private predicate fieldWrite(Field f, DataFlow::Node rhs) {
  any(Write w).writesField(_, f, rhs)
  or
  exists(CompositeLit lit, StructType st, int i, Expr elt, string name |
    st = initializedStructType(lit) and
    elt = lit.getElement(i) and
    f = st.getOwnField(name, _)
  |
    name = elt.(KeyValueExpr).getKey().(Ident).getName() and
    rhs = DataFlow::exprNode(elt.(KeyValueExpr).getValue())
    or
    not elt instanceof KeyValueExpr and
    st.hasOwnField(i, name, _, _) and
    rhs = DataFlow::exprNode(elt)
  )
}

/**
 * Holds if the function `fn` is written to the field `f`, either in a composite literal such as
 * `Sink{Handler: fn}` or in an assignment such as `s.Handler = fn`.
 */
private predicate functionStoredInField(Field f, DataFlow::FunctionNode fn) {
  exists(DataFlow::Node rhs, DataFlow::Node src |
    f.getType().getUnderlyingType() instanceof SignatureType and
    fieldWrite(f, rhs) and
    src = rhs.getAPredecessor*()
  |
    src = fn.getFunction().getARead() or
    src = fn
  )
}

/** Holds if `call` invokes the function value read from the field `f`, as in `s.f(...)`. */
private predicate callThroughField(DataFlow::CallNode call, Field f) {
  call.getCalleeNode().(DataFlow::FieldReadNode).getField() = f
}

/** Holds if `fn` is already a resolved callee of `call`. */
private predicate isResolvedCallee(DataFlow::CallNode call, DataFlow::FunctionNode fn) {
  exists(DataFlow::Callable c | c = call.getACalleeIncludingExternals() |
    c.asFunction() = fn.getFunction() or
    c.asFuncLit() = fn.asExpr()
  )
}

/**
 * Holds if `call` invokes `fn` through a function-typed struct field and `fn` is not already a
 * resolved callee of `call`.
 */
private predicate unresolvedFieldDispatch(DataFlow::CallNode call, DataFlow::FunctionNode fn) {
  exists(Field f |
    callThroughField(call, f) and
    functionStoredInField(f, fn) and
    not isResolvedCallee(call, fn)
  )
}

/**
 * A taint step from an argument of a call through a function-typed struct field to the
 * corresponding parameter of each function that is stored in that field.
 */
class FunctionFieldDispatchStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(DataFlow::CallNode call, DataFlow::FunctionNode fn, int i |
      unresolvedFieldDispatch(call, fn) and
      pred = call.getArgument(i) and
      succ = fn.getParameter(i)
    )
  }
}
