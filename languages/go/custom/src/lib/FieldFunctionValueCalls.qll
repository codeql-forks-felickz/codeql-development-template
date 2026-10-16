/**
 * Provides a lightweight extension of the Go call graph for calls made through
 * function values stored in struct fields.
 *
 * The standard Go data-flow library only resolves the target of a call through a
 * function value when that value reaches the call target by local flow or through a
 * global variable. A common dispatch pattern stores function values in struct
 * fields, for example `Sink{Wrapper: osReadFile}`, and later calls them as
 * `s.Wrapper(payload)`. Such calls have no resolved callee, so taint stops at the
 * call. This library resolves these calls field-sensitively: a call through field
 * `f` may target any function or function literal that is written to `f`.
 */

import go

/**
 * Gets a function (declared function or function literal) whose value may be held
 * by `n`, following local flow, global variables and the results of resolved calls
 * (for example factories that return a function literal).
 */
private DataFlow::FunctionNode getAFunctionValue(DataFlow::Node n) {
  n = result.(DataFlow::FuncLitNode)
  or
  n = result.getFunction().getARead()
  or
  result = getAFunctionValue(n.getAPredecessor())
  or
  exists(DataFlow::CallNode factory, DataFlow::ResultNode ret, int i |
    n = factory.getResult(i) and
    ret.getRoot() = factory.getACallee() and
    ret.getIndex() = i and
    result = getAFunctionValue(ret)
  )
}

/**
 * Holds if `rhs` initializes field `f` of a composite literal whose type has been
 * elided inside an enclosing slice, array or map literal of pointers, as in
 * `[]*T{{F: rhs}}`.
 *
 * The extractor gives such literals the pointer type `*T`, so they are not
 * `StructLit`s and their field initializations are not modeled as field writes.
 */
private predicate elidedPointerStructLitInitializesField(Field f, DataFlow::Node rhs) {
  exists(CompositeLit lit, StructType st, int i, string name |
    st = lit.getType().getUnderlyingType().(PointerType).getBaseType().getUnderlyingType() and
    f.getDeclaringType() = st and
    f.getName() = name and
    rhs.asExpr() = lit.getValue(i)
  |
    lit.getKey(i).(Ident).getName() = name
    or
    not exists(lit.getKey(i)) and st.hasOwnField(i, name, _, _)
  )
}

/** Gets a function or function literal that is written to field `f`. */
private DataFlow::FunctionNode getAFunctionStoredInField(Field f) {
  exists(DataFlow::Node rhs |
    any(Write w).writesField(_, f, rhs)
    or
    elidedPointerStructLitInitializesField(f, rhs)
  |
    result = getAFunctionValue(rhs)
  )
}

/**
 * Gets a function or function literal that may be the target of `call`, which is
 * a call through a function value read from struct field `f` and has no callee
 * resolved by the standard library.
 */
DataFlow::FunctionNode getAFieldFunctionValueCallee(DataFlow::CallNode call, Field f) {
  not exists(call.getACalleeIncludingExternals()) and
  call.getCalleeNode().(DataFlow::FieldReadNode).getField() = f and
  result = getAFunctionStoredInField(f)
}

/**
 * Holds if `pred` is the `i`th argument of a call through a function value stored
 * in a struct field and `succ` is the `i`th parameter of a function that may be
 * stored in that field.
 */
predicate fieldFunctionValueArgumentStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(DataFlow::CallNode call, DataFlow::FunctionNode callee, int i |
    callee = getAFieldFunctionValueCallee(call, _) and
    pred = call.getArgument(i) and
    succ = callee.getParameter(i)
  )
}
