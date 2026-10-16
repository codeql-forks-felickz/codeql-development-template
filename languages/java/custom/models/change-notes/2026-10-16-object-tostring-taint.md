---
category: minorAnalysis
---
* Added a taint summary for `java.lang.Object.toString()`. Kotlin compiles `x.toString()` on Java types that do not redeclare `toString` (for example `editText.text.toString()`) to `Object.toString()`, so taint from Android `EditText.getText()` was lost before reaching sinks such as `Runtime.exec`. `java/command-line-injection` and other taint queries now report these Kotlin flows.
