---
category: minorAnalysis
---
* The `py/hardcoded-credentials` query now reports hard-coded web framework signing secrets: Flask `app.secret_key`, `app.config["SECRET_KEY"]` and `app.config.update(SECRET_KEY=...)`, module-level `SECRET_KEY` in Django settings modules, the `SIGNING_KEY` entry of the SimpleJWT `SIMPLE_JWT` settings dictionary, and the `key` argument of PyJWT `jwt.encode` / `jwt.decode` (modeled with the new `credentials-key` sink kind). Any non-empty string literal is reported for these sinks, except when the same setting is also read from the environment in the same file, or the file is in a test location.
