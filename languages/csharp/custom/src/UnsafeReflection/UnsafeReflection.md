# Use of externally-controlled input to select classes or code

Passing a user-controlled type or assembly name to reflection APIs such as `Activator.CreateInstance`, `AppDomain.CreateInstanceAndUnwrap`, `Assembly.CreateInstance` or `Type.InvokeMember` lets an attacker choose which loadable type is instantiated or invoked. Constructors, static initializers and invoked members of unintended types can have dangerous side effects.

The query also follows type names through `Type.GetType`, `Assembly.GetType` and `Module.GetType` to the resulting `Type` object.

## Recommendation

Map user input to a fixed set of types on the server, for example with a dictionary from a short key to a `Type`, or check the requested name against an allowlist before resolving it.

## Example

The following code instantiates a type named by a query-string parameter:

```csharp
string data = req.QueryString["id"];
var container = Activator.CreateInstance(null, data); // BAD
```

The fixed version only accepts allowlisted type names:

```csharp
if (AllowedTypes.Contains(typeName))
{
    return Activator.CreateInstance(Type.GetType(typeName)); // GOOD
}
```

## References

- OWASP: [Unsafe use of Reflection](https://owasp.org/www-community/vulnerabilities/Unsafe_use_of_Reflection).
- Common Weakness Enumeration: [CWE-470](https://cwe.mitre.org/data/definitions/470.html).
