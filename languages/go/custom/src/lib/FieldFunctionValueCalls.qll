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
import semmle.go.dataflow.ExternalFlow

/**
 * Gets a function (declared function or function literal) whose value may be held
 * by `n`, following local flow, global variables, resolved call arguments and results
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
  or
  exists(
    DataFlow::CallNode call, DataFlow::ParameterNode p, DataFlow::FunctionNode callee, int i
  |
    n = p and
    p.getPosition() = i and
    callee.getParameter(i) = p and
    call.getACalleeIncludingExternals().asFunction() = callee.getFunction() and
    result = getAFunctionValue(call.getArgument(i))
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

/**
 * Holds if `sink` is an argument to a call through a function value stored in a
 * struct field, and the inferred target's corresponding argument is modeled as a
 * sink of `kind`.
 */
predicate fieldFunctionValueSink(DataFlow::Node sink, string kind) {
  exists(
    DataFlow::CallNode call, DataFlow::FunctionNode callee, int i, string package,
    string type, string name, string input
  |
    callee = getAFieldFunctionValueCallee(call, _) and
    exists(Function f |
      f = callee.getFunction() and
      (
        type = "" and f.hasQualifiedName(package, name)
        or
        f.(Method).hasQualifiedName(package, type, name)
      )
    ) and
    sinkModel(package, type, _, name, _, _, input, kind, _, _) and
    i = inputArgument(input) and
    sink = call.getArgument(i)
  )
}

bindingset[input]
private int inputArgument(string input) {
  result = input.regexpCapture("^Argument\\[([0-9]+)\\]$", 1).toInt()
  or
  exists(string firstString, string lastString |
    input.regexpCapture("^Argument\\[([0-9]+)\\.\\.([0-9]+)\\]$", 1) = firstString and
    input.regexpCapture("^Argument\\[([0-9]+)\\.\\.([0-9]+)\\]$", 2) = lastString and
    result = [firstString.toInt() .. lastString.toInt()]
  )
}
