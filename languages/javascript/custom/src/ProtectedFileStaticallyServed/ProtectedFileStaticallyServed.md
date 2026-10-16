# Authentication-protected file is also statically served

Express applications often return some pages only to authenticated users, for example:

```javascript
router.get("/admin", verifyJWT, (req, res) => res.render("admin.html"));
```

If the file that such a route returns lies inside a directory that a static-file middleware (`express.static`, `connect.static`, `serve-static`, `koa-static`) serves to the public, anyone can download it directly, without passing the authentication check. A common cause is putting the Express `views` folder inside the public folder.

## How it works

1. Finds Express routes (not `use` calls) that register, before the final handler, a middleware whose name looks like an authentication or authorization check (for example `verifyJWT`, `requireLogin`, `ensureAuthenticated`, `isAdmin`, `passport.authenticate(...)`).
2. In the final handler, resolves the file returned by:
   - `res.render("name")`, relative to the folder set with `app.set("views", ...)` (or the default `views` folder). View names without an extension are matched against existing template files.
   - `res.sendFile(path)`, including the `{ root: ... }` option.
3. Reports the call if that file lies inside a statically served folder (dot-prefixed paths are ignored, because static-file middlewares do not serve dotfiles by default).

Folder paths are resolved with the same logic as `js/statically-served-credentials` (see `StaticFileServing/StaticFileServing.qll`).

## Recommendation

Keep protected files and view templates outside every statically served directory. For example, use a dedicated `public` folder for static assets and a separate `views` folder for templates.

## Example

```javascript
app.use(express.static("static"));
app.set("views", "static/views");

// BAD: `static/views/admin.html` can also be fetched as `/views/admin.html`
router.get("/admin", verifyJWT, (req, res) => res.render("admin.html"));
```

```javascript
app.use(express.static("public"));
app.set("views", "views");

// GOOD: the views folder is not served
router.get("/admin", verifyJWT, (req, res) => res.render("admin.html"));
```

## Limitations

- Authentication middleware is recognized only by name, and only when passed directly to the route (`router.use(auth)` guards are not modeled).
- Only constant view names and file paths are resolved. Absolute paths and paths containing `..` are not resolved.
- Files in a served folder that no protected route references (for example an unreferenced admin page) are not reported, because nothing in the code shows they are meant to be protected.

## References

- [CWE-552: Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [Express: Serving static files](https://expressjs.com/en/starter/static-files.html)
