---
category: newQuery
---
* Added `go/session-cookie-httponly-disabled` (CWE-1004), which reports `gorilla/sessions` and `gin-contrib/sessions` session cookie options whose `HttpOnly` field is explicitly set to `false`. The stock `go/cookie-httponly-not-set` query does not model these session libraries.
* Added `go/missing-jwt-signature-check-manual-decode` (CWE-347), which reports user-controlled JWTs whose payload segment is split off, base64-decoded and unmarshalled without any signature verification. The stock `go/missing-jwt-signature-check` query only covers JWT libraries.
