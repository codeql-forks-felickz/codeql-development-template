/**
 * @name HTTP server or client without resource limits
 * @description Serving HTTP without read timeouts, or reading a whole response body fetched
 *              with the timeout-less default HTTP client, lets a remote party hold
 *              connections open or stream unbounded data, exhausting goroutines, file
 *              descriptors or memory.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id go/file-upload-resource-handling
 * @tags security
 *       external/cwe/cwe-400
 */

import go

/**
 * Gets the name of a `net/http` serving function. The package-level versions use a default
 * server with no timeouts; the `http.Server` methods use the timeouts set on the receiver.
 */
string servingFunctionName() {
  result = ["ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS"]
}

/** Holds if `f` is a field of `net/http.Server` that bounds how long reading a request header may take. */
predicate isHeaderTimeoutField(Field f) {
  f.hasQualifiedName("net/http", "Server", ["ReadHeaderTimeout", "ReadTimeout"])
}

/**
 * An `http.Server` composite literal that does not set `ReadHeaderTimeout` or `ReadTimeout`.
 */
class ServerLitWithoutTimeouts extends StructLit {
  ServerLitWithoutTimeouts() {
    this.getType().hasQualifiedName("net/http", "Server") and
    // Positional literals set every field, so only keyed literals are considered.
    forall(Expr e | e = this.getAnElement() | e instanceof KeyValueExpr) and
    not exists(KeyValueExpr kv | kv = this.getAnElement() |
      kv.getKey().(Ident).getName() = ["ReadHeaderTimeout", "ReadTimeout"]
    )
  }

  /** Gets the data-flow node for the server value, taking its address if it is taken immediately. */
  DataFlow::Node getServerNode() {
    if this.getParent() instanceof AddressExpr
    then result = DataFlow::exprNode(this.getParent())
    else result = DataFlow::exprNode(this)
  }
}

/**
 * Gets `n`, or the operand of `n` if `n` is an explicit or implicit pointer dereference.
 */
DataFlow::Node derefOperandOrSelf(DataFlow::Node n) {
  result = n or result = n.(DataFlow::PointerDereferenceNode).getOperand()
}

/** Holds if `recv` is the receiver of a call that starts serving on an `http.Server`. */
predicate isServingReceiver(DataFlow::Node recv) {
  exists(Method m |
    m.hasQualifiedName("net/http", "Server", servingFunctionName()) and
    recv = m.getACall().getReceiver()
  )
}

/** Holds if `base` is the base of a write to a header-read timeout field of an `http.Server`. */
predicate isTimeoutWriteBase(DataFlow::Node base) {
  exists(DataFlow::Write w, Field f, DataFlow::Node written |
    isHeaderTimeoutField(f) and
    w.writesField(written, f, _) and
    base = derefOperandOrSelf([written, written.(DataFlow::PostUpdateNode).getPreUpdateNode()])
  )
}

module ServerConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = any(ServerLitWithoutTimeouts lit).getServerNode()
  }

  predicate isSink(DataFlow::Node sink) { isServingReceiver(sink) or isTimeoutWriteBase(sink) }
}

module ServerFlow = DataFlow::Global<ServerConfig>;

/** Holds if `lit` is served without any header-read timeout being configured on it. */
predicate servedWithoutTimeouts(ServerLitWithoutTimeouts lit) {
  exists(DataFlow::Node sink |
    ServerFlow::flow(lit.getServerNode(), sink) and isServingReceiver(sink)
  ) and
  not exists(DataFlow::Node sink |
    ServerFlow::flow(lit.getServerNode(), sink) and isTimeoutWriteBase(sink)
  )
}

/**
 * Gets a call that sends a request with the default `net/http` client, which has no
 * timeout, to a URL that is not a compile-time constant.
 */
DataFlow::CallNode defaultClientRequest() {
  exists(string name | name = ["Get", "Head", "Post", "PostForm"] |
    exists(Function f | f.hasQualifiedName("net/http", name) and result = f.getACall())
    or
    exists(Method m, DataFlow::ReadNode client |
      m.hasQualifiedName("net/http", "Client", name) and
      result = m.getACall() and
      client.reads(any(Variable v | v.hasQualifiedName("net/http", "DefaultClient"))) and
      DataFlow::localFlow(client, result.getReceiver())
    )
  ) and
  not exists(result.getArgument(0).getStringValue())
}

/**
 * Holds if `readAll` reads the whole body of the response to `request` into memory
 * without a size limit.
 */
predicate unboundedBodyRead(DataFlow::CallNode request, DataFlow::CallNode readAll) {
  request = defaultClientRequest() and
  readAll = any(Function f | f.hasQualifiedName(["io", "io/ioutil"], "ReadAll")).getACall() and
  exists(DataFlow::FieldReadNode body |
    body.getField().hasQualifiedName("net/http", "Response", "Body") and
    DataFlow::localFlow(request.getResult(0), derefOperandOrSelf(body.getBase())) and
    DataFlow::localFlow(body, readAll.getArgument(0))
  )
}

from Expr e, string msg
where
  exists(Function f |
    f.hasQualifiedName("net/http", servingFunctionName()) and
    e = f.getACall().asExpr() and
    msg =
      "This call serves HTTP with a default server that has no ReadHeaderTimeout, ReadTimeout or IdleTimeout, allowing slow clients to exhaust server resources."
  )
  or
  exists(ServerLitWithoutTimeouts lit |
    servedWithoutTimeouts(lit) and
    e = lit.getTypeExpr() and
    msg =
      "This HTTP server is started without ReadHeaderTimeout or ReadTimeout, allowing slow clients to exhaust server resources."
  )
  or
  exists(DataFlow::CallNode readAll |
    unboundedBodyRead(_, readAll) and
    e = readAll.asExpr() and
    msg =
      "This reads the entire body of a response fetched with the default HTTP client, which has no timeout, without limiting its size."
  )
select e, msg
