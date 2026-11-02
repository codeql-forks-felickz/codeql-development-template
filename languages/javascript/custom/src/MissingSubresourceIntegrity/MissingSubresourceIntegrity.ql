/**
 * @name Third-party script loaded without Subresource Integrity
 * @description Loading a version-pinned script from a third-party host, such as a
 *              public CDN, without an `integrity` attribute allows an attacker who
 *              compromises that host to execute arbitrary code in the page.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision medium
 * @id js/missing-subresource-integrity
 * @tags security
 *       external/cwe/cwe-829
 *       external/cwe/cwe-353
 */

import javascript
import semmle.javascript.security.FunctionalityFromUntrustedSource

/**
 * Holds if `host` is a public content delivery network that serves immutable,
 * version-pinned package files for which an integrity hash can be computed.
 */
bindingset[host]
predicate isPublicPackageCdn(string host) {
  host =
    [
      "cdn.jsdelivr.net", "fastly.jsdelivr.net", "gcore.jsdelivr.net", "unpkg.com",
      "cdnjs.cloudflare.com", "code.jquery.com", "ajax.googleapis.com", "ajax.aspnetcdn.com",
      "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com", "cdn.datatables.net",
      "cdn.skypack.dev", "esm.sh", "ga.jspm.io"
    ]
}

/** Holds if `host` refers to the local machine. */
bindingset[host]
predicate isLocalhost(string host) {
  host.regexpMatch("(?i)(localhost|127\\.0\\.0\\.1|\\[::1\\])(:[0-9]+)?")
}

/**
 * Holds if `path` (without query string) is a JavaScript file whose path
 * contains a pinned version number, such as `lib-1.2.3.min.js` or `lib@1.2/x.js`.
 */
bindingset[path]
predicate isVersionPinnedScriptPath(string path) {
  path.regexpMatch("(?i).*[@/_.-]v?[0-9]+\\.[0-9]+.*\\.m?js")
}

/**
 * A `<script>` element that loads a script from a third-party host without
 * a (non-empty) Subresource Integrity digest.
 */
class ThirdPartyScriptWithoutIntegrity extends HTML::ScriptElement {
  string host;

  ThirdPartyScriptWithoutIntegrity() {
    exists(string url, string path |
      url = this.getSourcePath().trim() and
      host = url.regexpCapture("(?i)^(?:https?:)?//(\\[[^\\]]+\\]|[^:/?#]+)(?::[0-9]+)?([^?#]*).*", 1).toLowerCase() and
      path = url.regexpCapture("(?i)^(?:https?:)?//(\\[[^\\]]+\\]|[^:/?#]+)(?::[0-9]+)?([^?#]*).*", 2) and
      not isLocalhost(host) and
      (isPublicPackageCdn(host) or isVersionPinnedScriptPath(path))
    ) and
    not exists(string digest | digest = this.getIntegrityDigest() and not digest.trim() = "")
  }

  /** Gets the host from which the script is loaded. */
  string getHost() { result = host }
}

from ThirdPartyScriptWithoutIntegrity script
where
  // Avoid duplicating alerts already reported by `js/functionality-from-untrusted-source`
  // and `js/functionality-from-untrusted-domain`.
  not script instanceof AddsUntrustedUrl
select script,
  "Script loaded from third-party host '" + script.getHost() +
    "' without a Subresource Integrity (integrity attribute) check."
