# Hard-coded credential in a statically served directory

Static-file middlewares such as `express.static`, `connect.static`, `serve-static` and `koa-static` make every file inside the served directory downloadable by anyone who can reach the server. If such a directory contains a file with a hard-coded password, API key or other secret, that credential is exposed to the public.

This query complements the standard `js/exposure-of-private-files` query. That query only reports serving well-known private locations (a `node_modules` folder, the project/home/root/working folder). It does not look inside an ordinary served folder such as `public`, so it does not report a credential file stored there.

## How it works

1. Finds calls to `express.static`, `connect.static`, `serve-static` and `koa-static`, and resolves the served folder from constant strings, `__dirname + "/dir"`, `path.join(...)`/`path.resolve(...)` and local data flow. Plain relative paths are resolved against the folder of the calling file and any enclosing folder containing a `package.json`.
2. Looks for hard-coded credentials in extracted files below that folder, using the shared sensitive-name heuristics (password and secret classifications) for:
   - JavaScript/TypeScript property writes and variable declarations initialized with a string literal (minified files are skipped),
   - JSON object properties,
   - YAML mappings.
3. Skips values that are empty or contain whitespace (e.g. form labels), and files under a dot-prefixed path (static-file middlewares ignore dotfiles by default).

## Recommendation

Do not store credentials in a publicly served directory. Move configuration files out of the served folder, and load secrets from environment variables or a secret store.

## Example

```javascript
const express = require("express");
const app = express();

// public/config.json contains { "password": "adminpixi" }
app.use(express.static("public")); // BAD: the credential can be downloaded
```

## Limitations

- Only files extracted by the JavaScript extractor are inspected (for example `.js`, `.ts`, `.json`, `.yml`/`.yaml`, `.html`). Files with other extensions, such as `.conf`, `.txt`, `.env` or `.properties`, are not present in the database, so credentials in them cannot be detected.
- Folders served with absolute paths or paths containing `..` are not resolved.
- This is a name-based heuristic (`@precision medium`), so it may report placeholder values.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
- [Express: Serving static files](https://expressjs.com/en/starter/static-files.html)
