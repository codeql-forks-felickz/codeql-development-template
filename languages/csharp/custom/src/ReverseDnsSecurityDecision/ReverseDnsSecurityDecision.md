# Security decision based on reverse DNS lookup

The owner of an IP address block controls the reverse DNS (PTR) records for those addresses, and DNS responses can be spoofed or poisoned. An attacker can therefore make the host name returned by a reverse lookup be any name they choose, including a name the application trusts. A reverse DNS name must not be used to authenticate or authorize a client.

This query reports host names (`HostName` or `Aliases`) from `Dns.GetHostEntry(IPAddress)`, `Dns.GetHostEntryAsync(IPAddress)`, or `Dns.GetHostByAddress` that are compared (with `==`, `Equals`, `StartsWith`, `EndsWith`, `Contains`, `Compare`, or `Regex.IsMatch`) as part of a condition or a returned Boolean value. A comparison is not reported when the only effect of the guarded branch is to log the resolved host name.

## Recommendation

Authenticate clients with a cryptographic mechanism such as TLS client certificates or signed tokens. If a network-based check is needed in addition to that, compare the IP address itself against an allow list.

## Example

The following example grants access when the reverse DNS name of the client matches a trusted host:

```csharp
IPHostEntry hostInfo = Dns.GetHostEntry(clientAddress);
if (hostInfo.HostName.Equals("trustme.example.com")) // BAD
{
    GrantAccess();
}
```

The following example checks the client address itself instead:

```csharp
if (trustedAddresses.Contains(clientAddress)) // GOOD (in addition to proper authentication)
{
    GrantAccess();
}
```

## References

- Common Weakness Enumeration: [CWE-350](https://cwe.mitre.org/data/definitions/350.html).
- Microsoft Learn: [Dns.GetHostEntry Method](https://learn.microsoft.com/en-us/dotnet/api/system.net.dns.gethostentry).
