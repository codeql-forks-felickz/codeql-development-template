/**
 * Provides a taint step that models calls through function-typed struct fields.
 *
 * The standard Go data-flow library only resolves the target of a call through a
 * function value when that value reaches the callee expression by local flow (or a
 * jump step); it has no general lambda-flow support. A function value that is
 * stored in a struct field (for example in a struct literal that is registered in a
 * global table, or the result of a factory function assigned as
 * `s.Handler, err = makeHandler(s)`) and later invoked as `x.Field(args)` in another
 * function therefore has no resolved callee, and taint passed as an argument (or
 * returned from the stored function) is lost.
 *
 * This step resolves such unresolved calls with a field-based approximation: a call
 * through field `f` may invoke any function value that flows into a write of `f`
 * anywhere in the program. Argument `i` of the call flows to parameter `i` of each
 * such function, except for method expressions, where argument zero flows to the
 * receiver and later arguments flow to the corresponding parameters. Result `i` of
 * each such function flows to result `i` of the call.
 */

import go

/**
 * Holds if `fn` is a function value: a function literal, or a reference to a named
 * function or method (including method values such as `v.m`) that is not itself
 * the callee of a call.
 */
private predicate isFunctionValue(DataFlow::Node fn) {
  fn instanceof DataFlow::FuncLitNode
  or
  fn = any(Function f).getARead() and
  not fn = any(DataFlow::CallNode c).getCalleeNode()
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

/** Holds if `rhs` is a value written to the function-typed field `f`. */
private predicate functionFieldWrite(DataFlow::Node rhs, Field f) {
  f.getType().getUnderlyingType() instanceof SignatureType and
  (any(Write w).writesField(_, f, rhs) or initializesFieldOfElidedPointerLit(rhs, f))
}

/** Tracks function values to writes of function-typed struct fields. */
private module FunctionValueToFieldConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isFunctionValue(source) }

  predicate isSink(DataFlow::Node sink) { functionFieldWrite(sink, _) }
}

private module FunctionValueToFieldFlow = DataFlow::Global<FunctionValueToFieldConfig>;

/**
 * Holds if `call` invokes the function stored in field `f`, and the standard library
 * could not resolve any callee for it.
 */
private predicate unresolvedFieldCall(DataFlow::CallNode call, Field f) {
  call.getCalleeNode().(DataFlow::FieldReadNode).getField() = f and
  not exists(call.getACalleeIncludingExternals())
}

/**
 * Holds if `call` is an unresolved call through a function-typed field that may
 * invoke the function value `fn`, because `fn` may be stored in that field.
 */
private predicate fieldCallTarget(DataFlow::CallNode call, DataFlow::Node fn) {
  exists(Field f, DataFlow::Node rhs |
    unresolvedFieldCall(call, f) and
    functionFieldWrite(rhs, f) and
    FunctionValueToFieldFlow::flow(fn, rhs)
  )
}

/** Holds if `fn` is a method expression: its read is a selector with a type-expression base. */
private predicate isMethodExpression(Function f, DataFlow::Node fn) {
  f instanceof Method and
  exists(SelectorExpr sel |
    fn = f.getARead() and
    sel = fn.asExpr() and
    sel.getBase() instanceof TypeExpr
  )
}

/** Holds if `p` is the node initialized by the `i`th argument of the function value `fn`. */
private predicate functionValueParameter(DataFlow::Node fn, int i, DataFlow::Node p) {
  p = fn.(DataFlow::FunctionNode).getParameter(i) and
  not exists(Function f | isMethodExpression(f, fn))
  or
  exists(Function f |
    fn = f.getARead() and
    not isMethodExpression(f, fn) and
    p = DataFlow::parameterNode(f.getParameter(i))
  )
  or
  exists(Function f |
    isMethodExpression(f, fn)
  |
    i = 0 and p = DataFlow::receiverNode(f.(Method).getReceiver())
    or
    i > 0 and p = DataFlow::parameterNode(f.getParameter(i - 1))
  )
}

/** Holds if `res` is the `i`th result of the function value `fn`. */
private predicate functionValueResult(DataFlow::Node fn, int i, DataFlow::ResultNode res) {
  res = fn.(DataFlow::FunctionNode).getResult(i)
  or
  exists(DataFlow::FunctionNode f |
    fn = f.getFunction().getARead() and
    res = f.getResult(i)
  )
}

/**
 * A taint step that models a call through a function-typed struct field: from an
 * argument of the call to the corresponding parameter of a function value stored in
 * that field, and from a result of that function value to the corresponding result
 * of the call.
 */
class FunctionFieldCallTaintStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(DataFlow::CallNode call, DataFlow::Node fn, int i | fieldCallTarget(call, fn) |
      pred = call.getArgument(i) and
      functionValueParameter(fn, i, succ)
      or
      functionValueResult(fn, i, pred) and
      succ = call.getResult(i)
    )
  }
}
