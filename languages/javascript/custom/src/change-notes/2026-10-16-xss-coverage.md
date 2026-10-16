---
category: newQuery
---
* Added a new query, `js/reflected-xss-via-fetched-url`, which detects reflected cross-site scripting where the server fetches a URL whose scheme and host are user-controlled (for example with `needle` or `axios`) and writes the response to an HTTP response.
* Added the `languages-javascript-custom-models` model pack. It models Angular `inject()`-based dependency injection, so that `inject(ActivatedRoute)` URL sources and `inject(DomSanitizer).bypassSecurityTrust*` sinks are recognized by the stock `js/xss` and `js/code-injection` queries. Previously these were only recognized when the service had a type annotation, for example through constructor injection.
* Added a new query, `js/template-autoescape-disabled`, which detects Swig, Nunjucks and Handlebars configurations that turn off HTML autoescaping.
* Added `client-api-response.model.yml` to the `languages-javascript-custom-models` pack. When the `response` threat model is enabled, it treats the resolved value of `fetch` as a source even when the promise is returned from a helper function, and adds taint summaries for `Object.values` and `react-native-base64` `decode`. This lets the stock `js/xss` and `js/code-injection` queries find second-order XSS where client code renders data returned by the application's own API.
