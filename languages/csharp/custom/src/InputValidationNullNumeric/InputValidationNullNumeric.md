# Unvalidated user-controlled integer in arithmetic or division

Integers parsed from user-controlled input (for example an HTTP query string parameter) can take any value in the range of their type, including `0`, `int.MinValue` and `int.MaxValue`.

* If such a value is used as the divisor of an integer division or remainder operation without first checking it for zero, an attacker can trigger a `DivideByZeroException` (CWE-369). An unhandled exception can be used for denial of service.
* If such a value is used as an operand of an addition, subtraction or multiplication in an unchecked context, the result can silently wrap around (CWE-190). The wrapped value can subvert later size, bounds or authorization logic.

## Recommendation

Validate user-controlled integers before using them in arithmetic:

* Check that a divisor is not zero (for example `if (data != 0)`) before dividing.
* Check that an operand is within a safe range (for example `if (data < int.MaxValue)`) before adding, subtracting or multiplying, or clamp the value with `Math.Min`, `Math.Max` or `Math.Clamp`.
* Alternatively, perform the arithmetic in a `checked` context and handle the resulting `OverflowException`.

## Example

In the following example, an integer parsed from the query string is used as a divisor without a zero check, and incremented without a range check:

```csharp
int data = int.Parse(req.QueryString["id"]);
resp.Write("100/" + data + " = " + (100 / data));   // BAD: may divide by zero
int next = data + 1;                                // BAD: may overflow
```

The following code validates the value first:

```csharp
int data = int.Parse(req.QueryString["id"]);
if (data != 0)
{
    resp.Write("100/" + data + " = " + (100 / data)); // GOOD: checked for zero
}
if (data < int.MaxValue)
{
    int next = data + 1;                              // GOOD: range checked
}
```

## References

* Common Weakness Enumeration: [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
* Common Weakness Enumeration: [CWE-369](https://cwe.mitre.org/data/definitions/369.html).
* Microsoft Learn: [checked and unchecked statements](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/statements/checked-and-unchecked).
