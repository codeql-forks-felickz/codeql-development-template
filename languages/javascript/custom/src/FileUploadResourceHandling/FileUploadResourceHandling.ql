/**
 * @name Unbounded file upload or resource handling
 * @description Accepting uploads, sessions, GraphQL queries, archive entries or downloads
 *              without type, size, capacity or cost limits allows an attacker to exhaust
 *              memory, disk space or CPU, or to store files of unexpected types.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id js/file-upload-resource-handling
 * @tags security
 *       external/cwe/cwe-400
 *       external/cwe/cwe-409
 *       external/cwe/cwe-434
 */

import javascript
import semmle.javascript.security.dataflow.RequestForgeryQuery as RequestForgeryQuery

/** Gets a reference to module `m`, either directly or through its default export. */
API::Node moduleRef(string m) {
  result = API::moduleImport(m) or
  result = API::moduleImport(m).getMember("default")
}

/** Holds if `obj` is an object literal whose properties are all statically known. */
predicate isClosedObjectLiteral(DataFlow::ObjectLiteralNode obj) {
  not obj.asExpr().(ObjectExpr).getAProperty() instanceof SpreadProperty
}

/** Holds if `obj` defines (or later writes) a property named `name`. */
predicate hasProperty(DataFlow::ObjectLiteralNode obj, string name) {
  obj.hasPropertyWrite(name, _)
}

/** Holds if a multer instance escapes through an argument or module export. */
predicate multerInstanceEscapes(DataFlow::CallNode call) {
  exists(DataFlow::CallNode argument |
    argument.getAnArgument().getALocalSource() = call
  )
  or
  exists(DataFlow::PropWrite export |
    export.getPropertyName() = "exports" and
    export.getRhs().getALocalSource() = call
  )
}

/**
 * Holds if `call` configures a multer upload handler and `missing` describes the
 * validation that is absent from its options.
 */
predicate unrestrictedMulterUpload(DataFlow::CallNode call, string missing) {
  call = moduleRef("multer").getACall() and
  not (
    exists(call.getAMethodCall("none")) and
    not exists(call.getAMethodCall(["single", "array", "fields", "any"])) and
    not multerInstanceEscapes(call)
  ) and
  (
    not exists(call.getArgument(0)) and
    missing = "file type validation (fileFilter) or file size limit (limits.fileSize)"
    or
    exists(DataFlow::ObjectLiteralNode opts, boolean noFilter, boolean noSize |
      opts = call.getArgument(0).getALocalSource() and
      isClosedObjectLiteral(opts) and
      (if hasProperty(opts, "fileFilter") then noFilter = false else noFilter = true) and
      (
        if
          not hasProperty(opts, "limits")
          or
          exists(DataFlow::ObjectLiteralNode limits |
            opts.hasPropertyWrite("limits", limits.getALocalUse()) and
            isClosedObjectLiteral(limits) and
            not hasProperty(limits, "fileSize")
          )
        then noSize = true
        else noSize = false
      ) and
      (
        noFilter = true and
        noSize = true and
        missing = "file type validation (fileFilter) or file size limit (limits.fileSize)"
        or
        noFilter = true and
        noSize = false and
        missing = "file type validation (fileFilter)"
        or
        noFilter = false and noSize = true and missing = "file size limit (limits.fileSize)"
      )
    )
  )
}

/**
 * Holds if `call` configures express-session with the default in-process `MemoryStore`,
 * which has no capacity limit and leaks memory under load.
 */
predicate sessionWithDefaultMemoryStore(DataFlow::CallNode call) {
  call = moduleRef("express-session").getACall() and
  exists(DataFlow::ObjectLiteralNode opts |
    opts = call.getArgument(0).getALocalSource() and
    isClosedObjectLiteral(opts) and
    not hasProperty(opts, "store")
  )
}

/** Gets the configuration object passed to a GraphQL HTTP server. */
DataFlow::ObjectLiteralNode graphQLServerConfig() {
  exists(DataFlow::Node arg |
    exists(API::Node handler |
      handler = moduleRef("express-graphql") or
      handler = moduleRef("express-graphql").getMember("graphqlHTTP") or
      handler =
        moduleRef([
            "graphql-http", "graphql-http/lib/use/express", "graphql-http/lib/use/http",
            "graphql-http/lib/use/koa", "graphql-http/lib/use/fastify"
          ]).getMember("createHandler")
    |
      arg = handler.getACall().getArgument(0)
    )
    or
    arg =
      moduleRef([
          "apollo-server", "apollo-server-express", "apollo-server-koa", "apollo-server-hapi",
          "apollo-server-fastify", "apollo-server-lambda", "apollo-server-micro", "@apollo/server"
        ]).getMember("ApolloServer").getAnInstantiation().getArgument(0)
  |
    result = arg.getALocalSource()
    or
    // Options may be computed per request, e.g. `graphqlHTTP((req, res) => ({ ... }))`.
    result = arg.getALocalSource().(DataFlow::FunctionNode).getAReturn().getALocalSource()
  )
}

/** Holds if `rule` limits query cost, complexity or aliases. */
predicate isCostLimitingRule(DataFlow::Node rule) {
  exists(string name | name.regexpMatch("(?i).*(complexity|cost|alias).*") |
    name = rule.(DataFlow::InvokeNode).getCalleeName()
    or
    name = rule.asExpr().(VarAccess).getName()
    or
    exists(API::Node member | member = API::moduleImport(name).getAMember*() |
      rule = member.getACall() or rule = member.getAValueReachableFromSource()
    )
  )
}

/**
 * Holds if `rules` is the statically known list of `validationRules` of a GraphQL server
 * that does not limit query cost, complexity or aliases.
 */
predicate graphQLWithoutCostLimit(DataFlow::ArrayCreationNode rules) {
  exists(DataFlow::ObjectLiteralNode config |
    config = graphQLServerConfig() and
    isClosedObjectLiteral(config) and
    config.hasPropertyWrite("validationRules", rules.getALocalUse()) and
    not rules.asExpr().(ArrayExpr).getAnElement() instanceof SpreadElement and
    not isCostLimitingRule(rules.getAnElement()) and
    not exists(DataFlow::ArrayCreationNode plugins |
      config.hasPropertyWrite("plugins", plugins.getALocalUse()) and
      isCostLimitingRule(plugins.getAnElement())
    )
  )
}

/**
 * Holds if `use` expands (reads the decompressed contents of) the archive entry `entry`.
 */
predicate expandsEntry(DataFlow::SourceNode entry, DataFlow::MethodCallNode use) {
  use = entry.getAMethodCall(["pipe", "stream", "buffer"])
}

/** Holds if the expanded size of an archive entry is checked in the container of `use`. */
predicate checksExpandedSize(DataFlow::Node use) {
  exists(DataFlow::PropRead size |
    size.getPropertyName() = "uncompressedSize" and
    size.getContainer().getEnclosingContainer*() = use.getContainer()
  )
}

/** Holds if `stream` is the unzipper `Parse` stream `parse`, possibly as the result of `pipe`. */
predicate isParseStream(DataFlow::Node stream, DataFlow::CallNode parse) {
  stream.getALocalSource() = parse
  or
  exists(DataFlow::MethodCallNode pipe |
    pipe.getMethodName() = "pipe" and
    pipe.getArgument(0).getALocalSource() = parse and
    stream.getALocalSource() = pipe
  )
}

/**
 * Holds if `call` opens or parses an archive with unzipper and expands its entries
 * without limiting their expanded size.
 */
predicate unboundedArchiveExtraction(DataFlow::CallNode call) {
  call = moduleRef("unzipper").getMember("Extract").getACall()
  or
  exists(API::CallNode open, DataFlow::MethodCallNode use |
    open = moduleRef("unzipper").getMember("Open").getAMember().getACall() and
    call = open and
    expandsEntry(open.getReturn()
          .getPromised()
          .getMember("files")
          .getArrayElement()
          .getAValueReachableFromSource()
          .getALocalSource(), use) and
    not checksExpandedSize(use)
  )
  or
  exists(DataFlow::MethodCallNode on, DataFlow::FunctionNode handler, DataFlow::MethodCallNode use |
    call = moduleRef("unzipper").getMember(["Parse", "ParseOne"]).getACall() and
    on.getMethodName() = ["on", "once"] and
    on.getArgument(0).getStringValue() = "entry" and
    isParseStream(on.getReceiver(), call) and
    handler = on.getCallback(1) and
    expandsEntry(handler.getParameter(0), use) and
    not checksExpandedSize(use)
  )
  or
  exists(DataFlow::SourceNode stream, DataFlow::MethodCallNode use |
    call = moduleRef("unzipper").getMember("ParseOne").getACall() and
    isParseStream(stream, call) and
    use = stream.getAMethodCall(["pipe", "buffer"])
  )
}

/** Holds if `node` is a writable file stream. */
predicate isFileWriteStream(DataFlow::Node node) {
  node.getALocalSource().(DataFlow::CallNode).getCalleeName() = "createWriteStream"
}

/**
 * Holds if `call` writes the readable stream `data` to a file, either through
 * `data.pipe(file)` or `pipeline(data, ..., file)`.
 */
predicate writesStreamToFile(DataFlow::CallNode call, DataFlow::Node data) {
  call.(DataFlow::MethodCallNode).getMethodName() = "pipe" and
  isFileWriteStream(call.getArgument(0)) and
  not exists(DataFlow::MethodCallNode previousPipe |
    previousPipe.getMethodName() = "pipe" and
    call.(DataFlow::MethodCallNode).getReceiver().getALocalSource() = previousPipe
  ) and
  data = call.(DataFlow::MethodCallNode).getReceiver()
  or
  call.getCalleeName() = "pipeline" and
  not exists(call.getArgument(2)) and
  isFileWriteStream(call.getAnArgument()) and
  data = call.getArgument(0)
}

/** Flow from a request to a user-controlled URL to a file write without a size limit. */
module UnboundedDownloadConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::Node sink |
      RequestForgeryQuery::RequestForgeryFlow::flowTo(sink) and
      source = sink.(RequestForgeryQuery::Sink).getARequest()
    )
  }

  predicate isSink(DataFlow::Node sink) { writesStreamToFile(_, sink) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // The response object of a request.
    succ = pred.(ClientRequest).getAResponseDataNode()
    or
    // The response stream of a Node.js `http`/`https` request, e.g. `https.get(url, res => ...)`.
    exists(NodeJSLib::NodeJSClientRequest req | pred = req |
      succ = req.getLastArgument().getAFunctionValue().getParameter(0)
      or
      exists(DataFlow::MethodCallNode on |
        on = req.getAMethodCall(EventEmitter::on()) and
        on.getArgument(0).mayHaveStringValue("response") and
        succ = on.getCallback(1).getParameter(0)
      )
    )
    or
    // The body stream of a response, e.g. `response.body` or `response.data`.
    succ.(DataFlow::PropRead).getBase() = pred and
    succ.(DataFlow::PropRead).getPropertyName() = ["body", "data"]
    or
    // Converting a web stream into a Node.js stream, e.g. `Readable.fromWeb(response.body)`.
    exists(DataFlow::MethodCallNode convert |
      convert.getMethodName() = ["fromWeb", "from"] and
      convert.getReceiver().asExpr().(VarAccess).getName() = "Readable" and
      pred = convert.getArgument(0) and
      succ = convert
    )
    or
    // Chained event handler registrations return the stream itself.
    exists(DataFlow::MethodCallNode chain |
      chain.getMethodName() = ["on", "once", "setEncoding"] and
      pred = chain.getReceiver() and
      succ = chain
    )
  }
}

module UnboundedDownloadFlow = TaintTracking::Global<UnboundedDownloadConfig>;

from DataFlow::Node node, string message
where
  exists(string missing |
    unrestrictedMulterUpload(node, missing) and
    message = "This multer upload handler accepts files without " + missing + "."
  )
  or
  sessionWithDefaultMemoryStore(node) and
  message = "This session middleware uses the default in-memory store, which has no capacity limit."
  or
  graphQLWithoutCostLimit(node) and
  message = "These GraphQL validation rules do not limit query cost, complexity or aliases."
  or
  unboundedArchiveExtraction(node) and
  message = "This archive is extracted without a limit on the expanded size of its entries."
  or
  exists(DataFlow::Node data |
    writesStreamToFile(node, data) and
    UnboundedDownloadFlow::flowTo(data) and
    message = "The response from a user-controlled URL is written to a file without a size limit."
  )
select node, message
