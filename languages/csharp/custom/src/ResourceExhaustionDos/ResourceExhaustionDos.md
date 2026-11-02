# Uncontrolled resource consumption from user-provided value

Using a user-provided value as the bound of a loop, or as the size of an allocation, without first checking it against an upper limit allows an attacker to make the application spin for an unbounded amount of time or allocate an unbounded amount of memory. This can tie up request threads or exhaust memory, leading to a denial of service.

This query reports user-provided values (for example ASP.NET query string or form values) that reach:

- the upper bound of a loop condition, such as `n` in `for (int i = 0; i < n; i++)`, or the counter of a count-down loop such as `while (n > 0) { n--; }`;
- the length of an array creation, such as `new byte[n]`;
- the `capacity` argument of a collection, `StringBuilder` or stream constructor in `System.Collections*`, `System.Text` or `System.IO`;
- the `count` argument of `new string(char, int)`, `Enumerable.Repeat` or `Enumerable.Range`.

User-controlled regular expressions (CWE-1333) are reported by the standard `cs/regex-injection` query and are not reported by this query.

## Recommendation

Validate user-provided values that control loop bounds and allocation sizes against a reasonable upper limit before use, for example with an explicit comparison or by clamping the value with `Math.Min` or `Math.Clamp`.

## Example

In the following example, the number of loop iterations is read from the query string and is not checked against an upper limit:

```csharp
public void Bad(HttpRequest req)
{
    int numberOfLoops = int.Parse(req.Params.Get("name"));
    for (int i = 0; i < numberOfLoops; i++)
    {
        Console.WriteLine("hello world");
    }
}
```

The following example validates the value before using it as a loop bound:

```csharp
public void Good(HttpRequest req)
{
    int numberOfLoops = int.Parse(req.Params.Get("name"));
    if (numberOfLoops >= 0 && numberOfLoops <= 5)
    {
        for (int i = 0; i < numberOfLoops; i++)
        {
            Console.WriteLine("hello world");
        }
    }
}
```

## References

- Common Weakness Enumeration: [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- Common Weakness Enumeration: [CWE-606](https://cwe.mitre.org/data/definitions/606.html).
- Common Weakness Enumeration: [CWE-770](https://cwe.mitre.org/data/definitions/770.html).
- Common Weakness Enumeration: [CWE-789](https://cwe.mitre.org/data/definitions/789.html).
