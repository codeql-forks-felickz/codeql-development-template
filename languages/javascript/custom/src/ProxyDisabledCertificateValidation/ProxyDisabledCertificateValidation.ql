/**
 * @name Disabling certificate validation in HTTP proxy
 * @description Setting the `secure` option of an HTTP proxy to `false` disables TLS
 *              certificate validation for the connection to the proxied target.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.9
 * @precision high
 * @id js/proxy-disabled-certificate-validation
 * @tags security
 *       external/cwe/cwe-295
 */

import javascript

/**
 * Gets an options object passed to the `http-proxy` or `http-proxy-middleware` libraries,
 * whose `secure` property controls TLS certificate validation of the proxied target.
 */
API::Node proxyLibraryOptions() {
  exists(API::Node create |
    create =
      API::moduleImport("http-proxy")
          .getMember(["createServer", "createProxyServer", "createProxy"])
  |
    result = create.getParameter(0)
    or
    result = create.getReturn().getMember("web").getParameter(2)
    or
    result = create.getReturn().getMember("ws").getParameter([2, 3])
  )
  or
  exists(API::Node hpm | hpm = API::moduleImport("http-proxy-middleware") |
    result =
      hpm.getMember(["createProxyMiddleware", "legacyCreateProxyMiddleware"]).getParameter([0, 1])
    or
    result = hpm.getParameter([0, 1])
  )
}

/** Gets a Vite configuration object. */
DataFlow::SourceNode viteConfig() {
  exists(API::Node config |
    config = API::moduleImport("vite").getMember("defineConfig").getParameter(0)
  |
    result = config.asSink().getALocalSource()
    or
    result = config.getReturn().asSink().getALocalSource()
  )
  or
  exists(Module m | m.getFile().getStem() = "vite.config" |
    result = m.getAnExportedValue("default").getALocalSource()
  )
}

/** Gets the options object of a Vite dev-server or preview-server proxy rule. */
DataFlow::SourceNode viteProxyOptions() {
  result =
    viteConfig()
        .getAPropertySource(["server", "preview"])
        .getAPropertySource("proxy")
        .getAPropertySource()
}

from DataFlow::PropWrite disable
where
  (
    disable.getRhs() = proxyLibraryOptions().getMember("secure").asSink()
    or
    disable = viteProxyOptions().getAPropertyWrite("secure")
  ) and
  disable.getRhs().(AnalyzedNode).getTheBooleanValue() = false
select disable,
  "Disabling certificate validation of the proxied connection is strongly discouraged."
