---
category: newQuery
---
* Added a new query, `cs/json-injection`, which detects user-provided values that are concatenated, interpolated or formatted into JSON text that is then sent as a JSON `StringContent` request body or parsed with `System.Text.Json` or Newtonsoft.Json (CWE-74, CWE-116). C# had no query for this pattern.
