# Cross-site scripting through Swig templates with autoescaping disabled

This query reports user-controlled data rendered by Swig when global autoescaping is disabled.

The query requires a call to `swig.setDefaults` with `autoescape: false` and an escaping interpolation in a Swig template.

## Known limitations

- The query is heuristic and intended for a community pack. It does not model every template engine or every way autoescaping can be configured.
- Angular sanitizes ordinary `[innerHTML]` bindings by default. Such bindings are intentionally not reported unless a sanitizer bypass is separately identified.
- The Python extractor does not include `.html` templates, so this query does not cover Jinja `safe` filters in Python-only databases.
