# User-controlled loop bound with costly iterations

## Overview

If a user controls how many times a loop runs, and each iteration does work that grows with
the size of the data or allocates a new object, a single request can use a lot of CPU and
memory. Concurrent requests can make the application stop responding (CWE-400, CWE-606).

This query reports loops where a user-provided number (for example a request parameter
converted with `Integer.parseInt` or Commons Lang `NumberUtils.toInt`) controls the loop
condition, and the loop body does one of the following with a variable declared outside the
loop:

- concatenates immutable strings (`s = s + x` or `s += x`). Each iteration copies the whole
  string, so the total work grows with the square of the number of iterations.
- updates a boxed number (`Long sum; sum += i`). Each iteration allocates a new boxed object.

A loop is not reported if a top-level conjunct of its condition compares against a constant of
at most 10,000, or if the user-provided value is first checked against such a constant.

## Known limitations

- The condition check does not correlate a small-constant comparison with the loop's
  induction variable. A separate top-level conjunct can therefore suppress a finding even
  when it does not actually bound the iteration count.

## Recommendation

Check the user-provided value against a small upper limit before you use it as a loop bound.
Also make each iteration cheap: use a `StringBuilder` instead of string concatenation, and
primitive types (`long`) instead of boxed types (`Long`). Where possible, compute the result
directly, for example `n * (n + 1) / 2` instead of a summing loop.

## Example

In the following code, the user controls the number of iterations, and each iteration copies
the whole string built so far:

```java
int length = Integer.parseInt(req.getParameter("length"));
String s = "";
for (int i = 0; i < length && i < 1000000; i++) {
  s = s + characters[rand.nextInt(characters.length)];
}
```

The fixed version limits the length and uses a `StringBuilder`:

```java
int length = Math.min(Integer.parseInt(req.getParameter("length")), 1000);
StringBuilder builder = new StringBuilder(length);
for (int i = 0; i < length; i++) {
  builder.append(characters[rand.nextInt(characters.length)]);
}
```

In the next example, each iteration allocates a new `Long`:

```java
Long sum = 0L;
for (long i = 1; i <= number; i++) {
  sum += i;
}
```

The fixed version computes the sum directly:

```java
long sum = (long) number * (number + 1) / 2;
```

## References

- CWE: [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- CWE: [CWE-606: Unchecked Input for Loop Condition](https://cwe.mitre.org/data/definitions/606.html)
- Oracle: [Autoboxing and Unboxing](https://docs.oracle.com/javase/tutorial/java/data/autoboxing.html)
