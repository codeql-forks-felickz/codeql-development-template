---
category: newQuery
---

- Added a new query, `java/unsafe-deserialization-jackson-default-typing`, which complements
  `java/unsafe-deserialization` by reporting user-controlled data deserialized by a Jackson
  `ObjectMapper` whose default typing is enabled through `activateDefaultTyping` or
  `activateDefaultTypingAsProperty` with a `LaissezFaireSubTypeValidator`, or through the
  deprecated `enableDefaultTypingAsProperty`.
- Added a new model pack, `languages-java-custom-models`, with taint summaries for
  `javax.xml.bind.DatatypeConverter` and `jakarta.xml.bind.DatatypeConverter`
  (`parseBase64Binary` and `parseHexBinary`). This lets `java/unsafe-deserialization` (and other
  taint-tracking queries) follow user input that is Base64-decoded with these APIs, for example
  into `ObjectInputStream.readObject`.
