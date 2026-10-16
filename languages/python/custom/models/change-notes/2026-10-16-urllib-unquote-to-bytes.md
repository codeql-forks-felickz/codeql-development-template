---
category: minorAnalysis
---

- Added a taint summary model for `urllib.parse.unquote_to_bytes`, so that user input decoded with it is tracked into sinks such as XML parsing (`py/xxe`) and deserialization (`py/unsafe-deserialization`).
