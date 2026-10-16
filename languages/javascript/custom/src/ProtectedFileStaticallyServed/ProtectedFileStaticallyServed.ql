/**
 * @name Authentication-protected file is also statically served
 * @description A route returns a file (a rendered view or a file sent with `res.sendFile`)
 *              only after an authentication middleware, but the same file lies inside a
 *              directory that a static-file middleware serves to the public. The file can
 *              then be downloaded directly, bypassing the authentication check.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id js/protected-file-statically-served
 * @tags security
 *       external/cwe/cwe-552
 *       external/cwe/cwe-284
 *       external/cwe/cwe-538
 */

import javascript
import StaticFileServing.StaticFileServing

/**
 * Gets a name for the route handler `handler`, as written at the route setup.
 */
string handlerName(DataFlow::Node handler) {
  result = handler.asExpr().(VarAccess).getName()
  or
  result = handler.asExpr().(PropAccess).getPropertyName()
  or
  result = handler.(DataFlow::CallNode).getCalleeName()
  or
  result = handler.getAFunctionValue().getName()
}

/**
 * Holds if `name` looks like the name of an authentication or authorization middleware.
 */
bindingset[name]
predicate isAuthMiddlewareName(string name) {
  name.regexpMatch("(?i).*(auth|jwt|login|logged|token|session|permission|role|admin|guard|protect|verify|ensure|restrict|acl|signed).*")
}

/**
 * Holds if `setup` registers the middleware `mw`, named `name`, before its final handler,
 * and `mw` looks like an authentication check.
 */
predicate isProtectedRoute(Express::RouteSetup setup, DataFlow::Node mw, string name) {
  not setup.isUseCall() and
  exists(int i |
    mw = setup.getRouteHandlerNode(i) and
    mw != setup.getLastRouteHandlerNode() and
    name = handlerName(mw) and
    isAuthMiddlewareName(name)
  )
}

/**
 * Gets the path, relative to the source root, of the views folder used by `render`.
 */
string viewsFolderPath(DataFlow::MethodCallNode render) {
  exists(DataFlow::MethodCallNode setting |
    setting = viewsSetting() and
    (
      // prefer a setting in the same file, otherwise use any setting in the program
      setting.getFile() = render.getFile()
      or
      not viewsSetting().getFile() = render.getFile()
    ) and
    result = resolvedPath(setting.getArgument(1))
  )
  or
  not exists(viewsSetting()) and
  result = joinPath(getAWorkingFolder(render.getFile()).getRelativePath(), "views")
}

/**
 * Gets the path, relative to the source root, of the file returned by `call`, a call to
 * `res.render` or `res.sendFile` in the route handler `rh`.
 */
string returnedFilePath(Express::RouteHandler rh, DataFlow::MethodCallNode call) {
  call.getReceiver() = rh.getAResponseNode() and
  (
    call.getMethodName() = "render" and
    exists(string name, string path |
      name = call.getArgument(0).getStringValue() and
      not name.matches("/%") and
      path = joinPath(viewsFolderPath(call), normalize(name)) and
      not path.regexpMatch("(.*/)?\\.\\.(/.*)?")
    |
      // `res.render("admin.html")`
      name.regexpMatch(".*\\.[^/.]+") and result = path
      or
      // `res.render("admin")`, resolved using the extension of an existing template
      not name.regexpMatch(".*\\.[^/.]+") and
      exists(File f | f.getRelativePath() = path + "." + f.getExtension()) and
      result = any(File f | f.getRelativePath() = path + "." + f.getExtension()).getRelativePath()
    )
    or
    call = sendFileCall() and
    (
      not exists(call.getOptionArgument(1, "root")) and
      result = resolvedPath(call.getArgument(0))
      or
      exists(string name |
        name = call.getArgument(0).getStringValue() and
        not name.matches("/%") and
        result = joinPath(resolvedPath(call.getOptionArgument(1, "root")), normalize(name)) and
        not result.regexpMatch("(.*/)?\\.\\.(/.*)?")
      )
    )
  )
}

from
  Express::RouteSetup setup, DataFlow::Node mw, string mwName, Express::RouteHandler rh,
  DataFlow::MethodCallNode call, string path, DataFlow::CallNode serve
where
  isProtectedRoute(setup, mw, mwName) and
  rh = setup.getLastRouteHandlerNode().getALocalSource() and
  path = returnedFilePath(rh, call) and
  serve =
    min(DataFlow::CallNode s |
      isServedPath(path, s)
    |
      s order by s.getFile().getRelativePath(), s.getStartLine(), s.getStartColumn()
    ) and
  mw =
    min(DataFlow::Node m |
      isProtectedRoute(setup, m, _)
    |
      m order by m.getStartLine(), m.getStartColumn()
    )
select call,
  "This route returns " + path +
    " only after the authentication middleware $@, but the file is also exposed to the public by $@.",
  mw, mwName, serve, "this static-file middleware"
