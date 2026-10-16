---
category: newQuery
---
* Added `java/android/exported-provider-without-permissions`, which finds Android content providers that are explicitly exported without any `permission`, `readPermission`, `writePermission` or `<path-permission>` protection (CWE-926). Providers with only one of `readPermission` or `writePermission` remain reported by `java/android/incomplete-provider-permissions`.
* Added `java/improper-webview-certificate-validation-null-safe`, which finds `onReceivedSslError` handlers that call `SslErrorHandler.proceed()` behind a null check or non-null assertion of the handler, such as Kotlin `handler?.proceed()` or `handler!!.proceed()` (CWE-295). The standard `java/improper-webview-certificate-validation` query misses these because the call is conditional, or its qualifier is not a direct access to the handler parameter.
* Added `java/android/file-provider-root-path`, which finds FileProvider paths configurations whose `<root-path>` entry shares the device root directory (CWE-668).
* Added `java/android/unsafe-package-context-code-loading`, which finds calls to `Context.createPackageContext` with both `CONTEXT_INCLUDE_CODE` and `CONTEXT_IGNORE_SECURITY` (CWE-94, CWE-749).
* Added `java/tomcat-context-httponly-disabled`, which finds Tomcat `<Context>` elements that disable `HttpOnly` session cookies with `useHttpOnly` (CWE-1004).
