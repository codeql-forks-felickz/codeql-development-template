/**
 * Provides an additional data-flow step that models calls through
 * function-valued struct fields.
 *
 * The Go call graph only resolves a call through a function value when the
 * function reaches the callee expression by local flow (or through a global
 * variable). A call such as `s.Handler(x)`, where `Handler` is a struct field
 * that was initialized elsewhere (for example in a route table), therefore has
 * no resolved callee, and taint stops at its arguments.
 *
 * This library approximates such calls in a field-based manner: an argument
 * of an unresolved call whose callee is read from field `f` flows to the
 * corresponding parameter of every function (or function literal) whose value
 * is written to `f`.
 */

import go

/**
 * Holds if `rhs` is the value written to field `f`, either by an assignment
 * (`s.F = rhs`) or by a composite literal initialization (`S{F: rhs}`).
 *
 * Composite literals are matched syntactically so that elided pointer
 * literals such as the elements of `[]*S{{F: rhs}}` (which have type `*S`
 * and are not `StructLit`s) are also covered.
 */
private predicate fieldWrite(Field f, DataFlow::Node rhs) {
  any(Write w).writesField(_, f, rhs)
  or
  exists(CompositeLit lit, StructType st, Expr elt, int idx, string name |
    (
      st = lit.getType().getUnderlyingType()
      or
      st = lit.getType().getUnderlyingType().(PointerType).getBaseType().getUnderlyingType()
    ) and
    elt = lit.getElement(idx) and
    f.getDeclaringType() = st and
    f.getName() = name
  |
    name = elt.(KeyValueExpr).getKey().(Ident).getName() and
    rhs.asExpr() = elt.(KeyValueExpr).getValue()
    or
    not elt instanceof KeyValueExpr and
    st.hasOwnField(idx, name, _, _) and
    rhs.asExpr() = elt
  )
}

/** Holds if `f` is a struct field with a function type. */
private predicate isFunctionField(Field f) {
  f.getType().getUnderlyingType() instanceof SignatureType
}

/**
 * Gets a node to which a reference to the function or function literal `fn`
 * may flow locally.
 */
private DataFlow::Node functionValue(FuncDef fn) {
  result = fn.(FuncDecl).getFunction().getARead()
  or
  result.asExpr() = fn.(FuncLit)
  or
  DataFlow::localFlowStep(functionValue(fn), result)
}

/**
 * Holds if a reference to the function or function literal `fn` is
 * written to the function-valued field `f`.
 */
private predicate functionStoredInField(FuncDef fn, Field f) {
  isFunctionField(f) and
  fieldWrite(f, functionValue(fn))
}

/**
 * Gets a node to which a value read from the function-valued field `f` may
 * flow locally.
 */
private DataFlow::Node functionFieldValue(Field f) {
  isFunctionField(f) and
  result.(DataFlow::FieldReadNode).getField() = f
  or
  DataFlow::localFlowStep(functionFieldValue(f), result)
}

/**
 * Holds if `call` has no resolved callee and invokes a function value that
 * was read from the field `f`, possibly via a local variable.
 */
private predicate unresolvedCallThroughField(DataFlow::CallNode call, Field f) {
  call.getCalleeNode() = functionFieldValue(f) and
  not exists(call.getACalleeIncludingExternals())
}

/**
 * Holds if `pred` is the `i`th argument of a call through a function-valued
 * field and `succ` is the `i`th parameter of a function that may be stored
 * in that field.
 */
predicate functionFieldDispatchStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(DataFlow::CallNode call, Field f, FuncDef fn, int i |
    unresolvedCallThroughField(call, f) and
    functionStoredInField(fn, f) and
    not fn.isVariadic() and
    call.getNumArgument() = fn.getNumParameter() and
    pred = call.getArgument(i) and
    succ = DataFlow::parameterNode(fn.getParameter(i))
  )
}
