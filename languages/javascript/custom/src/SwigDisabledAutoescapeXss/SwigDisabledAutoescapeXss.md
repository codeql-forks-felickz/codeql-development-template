# Cross-site scripting through Swig templates with autoescape disabled

Swig escapes `{{value}}` by default. If an application explicitly disables autoescaping with `swig.setDefaults({ autoescape: false })`, request-controlled values rendered through Express into those placeholders are inserted as raw HTML.

## Recommendation

Keep Swig autoescaping enabled. If raw HTML is required, sanitize it for the intended context before rendering.

## Limitations

- The autoescape check is database-wide; it does not associate the setting with a particular Swig instance or Express application.
- Only values flowing directly from reflected HTTP request input to an Express `res.render` template parameter are modeled. Persisted database values, including the NodeGoat profile flow, are not covered.
- Django template filters such as `|safe` are not covered by this JavaScript query. The Python extractor does not provide template-placeholder modeling for those Django templates.
