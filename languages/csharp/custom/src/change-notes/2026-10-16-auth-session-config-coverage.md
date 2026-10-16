---
category: newQuery
---

- Added a new query, `cs/web/insecure-direct-object-reference-authorize-only`. It finds state-changing ASP.NET actions that take a resource ID and are protected only by a plain `[Authorize]` attribute, with no ownership or role check. The existing `cs/web/insecure-direct-object-reference` and `cs/web/missing-function-level-access-control` queries treat these actions as authorized.
- Added a new query, `cs/web/missing-service-operation-access-control`. It models WCF `[OperationContract]` service operations as endpoints and finds state-changing operations that take a resource ID and have no authorization.
- Added a new query, `cs/unsafe-certificate-validation-callback`. It finds TLS server certificate validation callbacks that unconditionally return `true`, including `HttpClientHandler.DangerousAcceptAnyServerCertificateValidator`.
