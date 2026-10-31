---
category: newQuery
---
* Added a new query, `cs/xml/xpath-injection-unresolved-controller`, which detects XPath injection (CWE-643) from parameters of ASP.NET Core controller actions when the controller base type (`ControllerBase` or `Controller`) could not be resolved, for example in `build-mode: none` databases of source files without a `Microsoft.NET.Sdk.Web` project file. In that situation `cs/xml/xpath-injection` does not recognize the action method parameters as remote flow sources. The new query only reports flows from these additional sources, so it does not duplicate `cs/xml/xpath-injection` results.
