---
category: minorAnalysis
---
* Added a `url-redirection` sink model for the ASP.NET Web Forms `System.Web.UI.WebControls.CreateUserWizard.ContinueDestinationPageUrl` property setter. The `cs/web/unvalidated-url-redirection` query now reports user-controlled values (for example a `ReturnUrl` query string parameter) assigned to this property, which the control later redirects to.
