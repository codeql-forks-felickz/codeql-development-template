/**
 * @name Folder with keys or secrets exposed over HTTP
 * @description Serving, listing or offering downloads from a folder whose name indicates that it
 *              holds cryptographic keys, certificates or other secrets lets anyone retrieve
 *              that material.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id js/sensitive-folder-exposed
 * @tags security
 *       external/cwe/cwe-548
 *       external/cwe/cwe-538
 *       external/cwe/cwe-552
 */

import javascript
import StaticFileServing.StaticFileServing

/**
 * Holds if the folder name `name` indicates that the folder holds keys, certificates or
 * other secrets.
 */
bindingset[name]
predicate isSensitiveFolderName(string name) {
  name.regexpMatch("(?i)(.*[_.-])?(encryption|private|secret|signing|api|ssh|jwt|crypto)?[_-]?(keys?|keystores?|keyrings?)([_.-].*)?") or
  name.regexpMatch("(?i)(.*[_.-])?(secrets?|credentials?|creds|certs?|certificates?|ssl|tls|pki|\\.ssh|\\.gnupg)([_.-].*)?") or
  name.regexpMatch("(?i)(encryption|private|secret|signing)keys?")
}

/**
 * Gets a description of the exposure kind `kind`.
 */
string describe(string kind) {
  kind = "static" and result = "Serves every file in"
  or
  kind = "listing" and result = "Serves a directory listing of"
  or
  kind = "download" and result = "Serves any requested file from"
}

from DataFlow::Node exposer, string kind, string rel, string name
where
  exposesFolder(exposer, kind, rel, _) and
  name = rel.splitAt("/") and
  isSensitiveFolderName(name)
select exposer,
  describe(kind) + " the folder '" + rel + "', whose name ('" + name +
    "') indicates that it holds keys or secrets."
