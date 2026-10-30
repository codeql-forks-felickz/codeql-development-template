# Folder with keys or secrets exposed over HTTP

A Node.js server that serves, lists or offers downloads from a folder whose name says that it holds keys, certificates or other secrets (for example `encryptionkeys`, `private-keys`, `secrets`, `certs`, `.ssh`) lets anyone retrieve that material.

The standard `js/exposure-of-private-files` query only reports serving `node_modules` or the project, home, root or working folder. It does not model `serve-index` directory listings or routes that send any requested file from a fixed folder, and it does not consider what the served folder is for.

The files in such folders (`.key`, `.pem`, `.pub`, `.p12`, ...) are usually not extracted into the CodeQL database, so their contents cannot be inspected. This query therefore relies on the folder name.

## How it works

The query reports a call that makes a folder reachable over HTTP:

- **static**: a static-file middleware (`express.static`, `connect.static`, `serve-static`, `koa-static`) serving the folder,
- **listing**: a [`serve-index`](https://npmjs.com/package/serve-index) middleware listing the folder,
- **download**: `res.sendFile(path.resolve("folder", file))`, `res.sendFile(path.join(__dirname, "folder", file))` or `res.download(file, { root: "folder" })` where `file` is not a constant.

The call is reported if any component of the folder path (for example `keys`, `encryptionkeys`, `private-keys`, `secrets`, `credentials`, `certs`, `ssl`, `tls`, `pki`, `.ssh`) indicates keys or secrets. Folder paths are resolved with the shared logic in `StaticFileServing/StaticFileServing.qll`. Response objects are recognized from the Express model or from an `express` `Response` type annotation, so handlers returned from factory functions are also covered.

## Recommendation

Keep key material and other secrets outside every folder that is served, listed or used for downloads. Load secrets from environment variables or a secret store instead.

## Example

```javascript
// BAD: lists and serves the private key folder
app.use("/encryptionkeys", serveIndex("encryptionkeys"));
app.use("/encryptionkeys/:file", (req, res) => {
  res.sendFile(path.resolve("encryptionkeys/", req.params.file));
});
```

## Limitations

- The query relies on the folder name. A folder with a neutral name that contains keys is not reported, and a folder whose name suggests secrets but holds only public material (for example a public certificate) is reported.
- A route that sends a single fixed file (for example `res.sendFile(path.resolve("ssl", "server.pem"))`) is not reported.
- Absolute paths and paths containing `..` are not resolved.

## References

- [CWE-548: Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)
- [CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
- [CWE-552: Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)
