# XML parser explicitly configured to resolve external entities

An XML parser that processes Document Type Definitions (DTDs) and also has an unrestricted `XmlResolver` resolves external entities declared in the document. If any part of the XML can be influenced by an attacker, an entity such as `<!ENTITY xxe SYSTEM "file:///etc/passwd">` can disclose local files or make the server issue requests to arbitrary hosts (XML External Entity, XXE).

On modern .NET, `XmlReader.Create` prohibits DTDs by default and `XmlTextReader` does not resolve external entities unless a resolver is assigned. This query therefore only reports parsers where the code explicitly opts in to both behaviours:

- `XmlReader.Create` called with `XmlReaderSettings` that set `DtdProcessing = DtdProcessing.Parse` (or `ProhibitDtd = false`) and assign a non-null `XmlResolver` such as `XmlUrlResolver`.
- `XmlTextReader` with a non-null `XmlResolver` assigned and DTD processing not disabled (`XmlTextReader` parses DTDs by default).

Unlike `cs/xml/insecure-dtd-handling`, this query does not require the XML to come from a known remote source, because the configuration is unsafe for any input that is not fully trusted.

## Recommendation

Leave `DtdProcessing` at its default of `Prohibit` (or set it to `Ignore`), and do not assign an `XmlResolver`, or set it to `null`. If DTD processing is genuinely needed, set `XmlResolver = null` so external entities are not fetched.

## Known limitations

The query recognizes the last property assignment when the assignments are ordered in control flow. It does not distinguish settings writes on mutually exclusive branches.

## Example

The following reader resolves external entities because both DTD processing and an `XmlUrlResolver` are enabled:

```csharp
var settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Parse;
settings.XmlResolver = new XmlUrlResolver();
XmlReader reader = XmlReader.Create(stream, settings); // BAD
```

The fix is to keep DTD processing disabled and not assign a resolver:

```csharp
var settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
XmlReader reader = XmlReader.Create(stream, settings); // GOOD
```

## References

- OWASP: [XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html).
- Microsoft Learn: [XmlReaderSettings.DtdProcessing](https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings.dtdprocessing).
- Common Weakness Enumeration: [CWE-611](https://cwe.mitre.org/data/definitions/611.html).
- Common Weakness Enumeration: [CWE-827](https://cwe.mitre.org/data/definitions/827.html).
