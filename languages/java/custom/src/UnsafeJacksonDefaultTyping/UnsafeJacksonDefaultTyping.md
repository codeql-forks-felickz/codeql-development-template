# Deserialization of user-controlled data with permissive Jackson default typing

## Overview

Jackson "default typing" makes `ObjectMapper` read the concrete class to instantiate from the
JSON document itself (for example from an `@class` property). If the type validator passed to
`activateDefaultTyping` (or `activateDefaultTypingAsProperty`) accepts every type, as
`LaissezFaireSubTypeValidator` does, an attacker who controls the JSON can make Jackson
instantiate arbitrary classes on the classpath and invoke their setters. With a suitable gadget
class this leads to remote code execution.

This query complements the standard `java/unsafe-deserialization` query, which only recognizes
the deprecated `enableDefaultTyping` method. It reports user-controlled data (for example a
cookie value or request parameter, possibly Base64-decoded) that reaches `readValue`,
`readValues` or `treeToValue` on an `ObjectMapper` configured with:

- `activateDefaultTyping(...)` or `activateDefaultTypingAsProperty(...)` with a
  `LaissezFaireSubTypeValidator`, or
- the deprecated `enableDefaultTypingAsProperty(...)`.

## Recommendation

Do not enable default typing for untrusted input. Bind the input to a fixed class instead. If
polymorphic deserialization is required, use a `BasicPolymorphicTypeValidator` that only allows
an explicit set of trusted base types or packages, and integrity-protect (sign) data that makes a
round trip through the client.

## Example

The following mapper lets the JSON in a client-supplied cookie choose any class:

```java
ObjectMapper mapper = new ObjectMapper();
mapper.activateDefaultTyping(
    LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
Object result = mapper.readValue(Base64.getDecoder().decode(cookie.getValue()), Object.class);
```

Restrict the allowed types with an allowlisting validator, or avoid default typing entirely:

```java
ObjectMapper mapper = new ObjectMapper();
mapper.activateDefaultTyping(
    BasicPolymorphicTypeValidator.builder().allowIfSubType("com.example.model.").build(),
    ObjectMapper.DefaultTyping.NON_FINAL);
```

## References

- Jackson: [On Jackson CVEs: Don't Panic](https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062).
- Jackson: [Polymorphic Type Handling](https://github.com/FasterXML/jackson-docs/wiki/JacksonPolymorphicDeserialization).
- OWASP: [Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
