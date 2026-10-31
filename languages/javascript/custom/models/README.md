# Known limitations

## SSRF through external image utilities

An external image utility invoked through `child_process.exec` is not modeled as a request-forgery sink. The JavaScript API-graph model for `exec` can identify its command argument, but cannot distinguish a command that fetches a remote image from other tainted shell commands. Modeling that argument as a request-forgery sink would therefore flag arbitrary tainted commands as SSRF. The available string-argument filter requires a literal value and cannot narrowly match a command prefix followed by a dynamic URL.
