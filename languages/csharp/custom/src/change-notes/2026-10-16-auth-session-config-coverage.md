---
category: newQuery
---

- Added a new query, `cs/web/insecure-direct-object-reference-authorize-only`. It finds state-changing ASP.NET actions that take a resource ID and are protected only by a plain `[Authorize]` attribute, with no ownership or role check. The existing `cs/web/insecure-direct-object-reference` and `cs/web/missing-function-level-access-control` queries treat these actions as authorized.
- Added a new query, `cs/web/missing-service-operation-access-control`. It models WCF `[OperationContract]` service operations as endpoints and finds state-changing operations that take a resource ID and have no authorization.
- Added a new query, `cs/unsafe-certificate-validation-callback`. It finds TLS server certificate validation callbacks that unconditionally return `true`, including `HttpClientHandler.DangerousAcceptAnyServerCertificateValidator`.
- Added a new query, `cs/web/missing-authentication-state-changing-action`. It finds ASP.NET Core and MVC actions that change state (`POST`, `PUT`, `PATCH`, `DELETE` or state-changing names) with no authorization attribute, global authorization policy or current-user check, and actions where `[AllowAnonymous]` overrides a controller-level `[Authorize]`. Actions already reported by `cs/web/missing-function-level-access-control` are skipped.
- Added a new query, `cs/web/config-authorization-allows-all`. It finds application-wide `Web.config` `<allow users="*" />` rules in applications that configure Forms or Windows authentication but never deny anonymous users.
- Added a new query, `cs/web/webforms-request-forgery`. It finds ASP.NET Web Forms pages that call state-changing methods with values from `Request.Params`, `Request.QueryString` or `Request.Form` without anti-forgery validation, or outside an `IsPostBack` check on a page that sets `ViewStateUserKey`. The existing `cs/web/missing-token-validation` query only covers MVC and ASP.NET Core actions.
