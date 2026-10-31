---
category: newQuery
---

- Added a new query, `py/xpath-injection-extended`, which extends `py/xpath-injection`. It also tracks user-controlled values through local variables that are defined by iterable unpacking (for example `path, query = self.path.split("?", 1)`) and read in a nested scope, such as a generator expression or inner function.
- Added a new query, `py/str-format-template-injection`, which reports user-controlled format strings passed to `str.format`, `str.format_map` or `string.Formatter` (CWE-1336). Replacement fields such as `{1.environ}` can traverse the formatted objects and disclose secrets.
- Added a new query, `py/prompt-injection-extended`, which extends the experimental `py/prompt-injection` query with LlamaIndex LLM completion prompts (`complete`, `acomplete`, `stream_complete` and `astream_complete`), taint propagation through `string.Template` substitution, and LLM instances stored in `self` attributes by iterable unpacking (CWE-1427).
