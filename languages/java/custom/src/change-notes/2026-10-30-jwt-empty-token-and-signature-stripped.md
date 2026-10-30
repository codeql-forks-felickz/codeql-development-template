---
category: newQuery
---
* Added a new query, `java/jwt-empty-token-accepted`, to detect JWT validators that return `true` when the split token has zero parts, so a token such as `.` is accepted without a signature.
* Added a new query, `java/jwt-signature-stripped`, to detect JJWT unsigned parse methods (for example `parseClaimsJwt`) called on a token that was rebuilt without its signature.
