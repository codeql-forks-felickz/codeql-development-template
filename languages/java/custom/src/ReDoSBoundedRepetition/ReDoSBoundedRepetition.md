# Inefficient regular expression with large bounded repetition

## Overview

Some regular expressions take exponential time to match certain inputs because the
backtracking engine of `java.util.regex` tries every way of splitting the input between
nested quantifiers. A bounded repetition with a large upper bound, such as `{1,100}`, is
just as dangerous as `+` here: 30 or more iterations are enough for 2^30 steps.

For example, in `^([a-z0-9]+[-]{0,1}){1,100}$` the separator is optional, so a run of
letters or digits can be split between iterations of the outer group in many ways. An input
such as `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!` makes the matcher try all of them before it fails.
If the expression is applied to user input in a request handler, a few requests can keep
the server's CPUs busy (CWE-1333).

The standard `java/redos` query only considers terms nested inside an unbounded quantifier
(`*`, `+` or `{n,}`), so it does not report these expressions. This query uses the same
analysis, but also treats a repetition `{0,N}` or `{1,N}` with `N >= 30` as unbounded. It
only reports terms that `java/redos` does not already report.

## Recommendation

Change the regular expression so that each part of the input can be matched in only one
way. For example, make the separator mandatory between iterations:
`^[a-z0-9]+(-[a-z0-9]+)*-?$`. You can also use a possessive quantifier (`[a-z0-9]++`) or
an atomic group, or limit the length of the input before matching.

## Example

The following code matches a request parameter against an expression with a nested
quantifier inside `{1,100}`:

```java
String word = req.getParameter("word");
Pattern p = Pattern.compile("^([a-z0-9]+[-]{0,1}){1,100}$");
boolean matches = p.matcher(word).matches();
```

The fixed version accepts the same strings in linear time:

```java
Pattern p = Pattern.compile("^[a-z0-9]+(-[a-z0-9]+)*-?$");
```

## References

- OWASP: [Regular expression Denial of Service - ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- Wikipedia: [ReDoS](https://en.wikipedia.org/wiki/ReDoS)
- CWE: [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- CWE: [CWE-730: OWASP Top Ten 2004 Category A9 - Denial of Service](https://cwe.mitre.org/data/definitions/730.html)
- CWE: [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
