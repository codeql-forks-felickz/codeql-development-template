Host names returned by a reverse DNS lookup of an IP address are controlled by whoever controls the DNS (PTR) records for that address. An attacker can make their own IP address resolve to a trusted host name, so a condition that compares a reverse DNS host name with an expected value must not decide whether a sensitive action (such as logging a user in) is performed.

This query extends `cs/user-controlled-bypass` with reverse DNS sources it does not model: `Dns.GetHostEntry(IPAddress)` and `Dns.GetHostEntryAsync(IPAddress)`. It also models `Dns.GetHostByAddress`, which overlaps with the stock query for constant comparisons, and follows comparisons of the host name against non-constant values, such as a configured host name.

## Recommendation

Do not use reverse DNS to make security decisions. Authenticate the peer with a cryptographic mechanism (for example TLS client certificates), or, if network location must be used, compare the peer IP address against an allow-list of addresses.

## Example

In the following example, the user is logged in only when the reverse DNS host name of the peer matches a trusted host name. An attacker who controls the PTR record of their address can bypass this check.

```csharp
IPHostEntry hostInfo = Dns.GetHostEntry(peerAddress);
if (hostInfo.HostName.Equals("trusted.example.com"))
{
    Login(user, password);
}
```

Instead, base the decision on the peer address itself:

```csharp
if (AllowedAddresses.Contains(peerAddress))
{
    Login(user, password);
}
```

## References

- MITRE: [CWE-350: Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html).
- MITRE: [CWE-807: Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html).
