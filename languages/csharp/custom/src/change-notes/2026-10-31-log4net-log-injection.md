---
category: minorAnalysis
---
* Added the `languages-csharp-custom-models` model pack with `log-injection` sinks for the log4net `ILog` logging methods (`Debug`, `Info`, `Warn`, `Error`, `Fatal` and their `*Format` variants). The stock `cs/log-forging` query now reports user input logged through a log4net logger. Elements of the `params object[]` argument of the `*Format` overloads are not modeled.
