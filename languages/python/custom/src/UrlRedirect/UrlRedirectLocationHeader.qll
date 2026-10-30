/**
 * Provides additional sinks for the `py/url-redirection` query.
 *
 * The standard library models only treat dedicated redirect APIs (such as
 * `flask.redirect` or `django.shortcuts.redirect`) as redirect locations.
 * A response that sets the `Location` header directly, for example through
 * `BaseHTTPRequestHandler.send_header("Location", url)` in `http.server`,
 * redirects the client just the same and is modeled here.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.security.dataflow.UrlRedirectCustomizations

/**
 * The value written to a `Location` response header, considered as a flow sink
 * for URL redirection vulnerabilities.
 */
class LocationHeaderWriteAsSink extends UrlRedirect::Sink {
  LocationHeaderWriteAsSink() {
    exists(Http::Server::ResponseHeaderWrite write |
      write.getNameArg().asExpr().(StringLiteral).getText().toLowerCase() = "location" and
      this = write.getValueArg()
    )
  }
}
