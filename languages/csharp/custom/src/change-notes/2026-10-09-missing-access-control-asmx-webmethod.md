---
category: minorAnalysis
---
* The `cs/web/missing-function-level-access-control` query now models methods annotated with `[System.Web.Services.WebMethod]` (ASMX web service operations and ASP.NET page methods) as actions. Such methods are also considered sensitive when their names indicate a transfer, withdrawal, deposit, update or removal (for example `TransferBalance`), so unauthenticated ASMX operations are now reported.
