---
category: newQuery
---

- Added a new query, `go/cors-misconfiguration-extended`, which extends the experimental `go/cors-misconfiguration` query. In addition to request-derived and `null` origins with credentials, it reports a wildcard origin (`*`, `http://*` or `https://*`) combined with credentials or with explicitly allowed `PUT`, `PATCH` or `DELETE` methods. It covers both `net/http` header writes and the CORS middleware configuration of Echo (v3 and v4), `github.com/gin-contrib/cors`, `github.com/rs/cors` and `github.com/go-chi/cors`.
