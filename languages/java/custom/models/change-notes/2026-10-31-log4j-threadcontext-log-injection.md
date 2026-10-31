---
category: minorAnalysis
---
* Added `log-injection` sink models for the Log4j 2 Thread Context (`ThreadContext` and `CloseableThreadContext` `put`, `putIfNull`, `putAll`, `push` and `pushAll`). Values stored there are rendered into log lines by layout patterns such as `%X{key}` and `%x`, so `java/log-injection` now reports user-provided values (for example an `X-Forwarded-For` header) that reach the Thread Context without CR/LF neutralization (CWE-117).
