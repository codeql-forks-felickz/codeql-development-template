---
category: newQuery
---

- Added a new query, `js/stack-trace-exposure-extended`, which extends `js/stack-trace-exposure` with Express error-handler, Node.js-style callback and promise rejection errors as sources, error `message` reads, objects sent in responses, and the `errorhandler` middleware. Values and middleware guarded by a `development` environment check are not reported.
