# Web.config compilation debug mode enabled

## Overview

ASP.NET compilation debug mode should not be enabled in deployed applications. A
`<compilation debug="true" />` setting can expose detailed diagnostic information and
reduce application performance.

This query reports a `compilation` element in a Web.config file when its `debug`
attribute is `true`.

## Recommendation

Set `debug="false"` or remove the `debug` attribute before deploying the application.

## References

- Common Weakness Enumeration: [CWE-489](https://cwe.mitre.org/data/definitions/489.html).
