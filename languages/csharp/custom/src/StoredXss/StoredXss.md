# Stored cross-site scripting

Data that an application reads back from its database was often originally supplied by users, for example comments, e-mail addresses, or product names entered through an administration page. Writing such data to a web page without HTML-encoding it allows an attacker who can store data to run script in the browser of every user who views the page.

The standard `cs/web/xss` query only reports stored XSS when the `database` threat model is enabled. This query always treats database reads as sources, including Entity Framework mapped properties, `DbDataReader` results, and (through the `languages-csharp-custom-models` pack) values read from a `DataRow`. It reuses the sinks and sanitizers of `cs/web/xss`, so it follows values through helper methods (for example `ToSummaryHtml()`) into `Html.Raw`, `Label.Text`, `Literal.Text`, `InnerHtml`, and similar sinks.

## Recommendation

HTML-encode stored values when writing them to a page, for example with `HttpUtility.HtmlEncode`, or use controls and Razor expressions that encode automatically instead of `Html.Raw`, `Literal`, `Label`, or `InnerHtml`.

## Example

The following page loads comments from the database and writes them to a `Literal` control without encoding:

```csharp
foreach (DataRow row in ds.Tables[0].Rows)
{
    comments += "<strong>Comment:</strong>" + row["comment"];
}
lblComments.Text = comments;
```

Encode each stored value before building the HTML:

```csharp
foreach (DataRow row in ds.Tables[0].Rows)
{
    comments += "<strong>Comment:</strong>" + HttpUtility.HtmlEncode(row["comment"].ToString());
}
lblComments.Text = comments;
```

## References

- OWASP: [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
