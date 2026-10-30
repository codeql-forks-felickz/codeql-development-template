# Web Forms state change without CSRF protection

## Overview

ASP.NET Web Forms protects postbacks against cross-site request forgery (CSRF) only when the page validates its view state and binds it to the user with `ViewStateUserKey`. Values read directly from `Request.Params`, `Request.QueryString` or `Request.Form` are not covered by that protection, and they are also available on `GET` requests and on `POST` requests that are not postbacks.

A page that performs a state-changing operation, such as a money transfer or a database update, from these values can be triggered by an attacker who makes a logged-in victim's browser request the page, for example with an image tag or an auto-submitting form.

The existing `cs/web/missing-token-validation` query only covers ASP.NET MVC and ASP.NET Core actions.

This query reports calls to state-changing methods in Web Forms pages whose arguments depend on `Request.Params`, `Request.QueryString` or `Request.Form`, unless the page calls `AntiForgery.Validate()`, or the call only runs on a postback (`if (IsPostBack)`) in a page that sets `ViewStateUserKey`.

It also reports postback event handlers (for example `btnPlaceOrder_Click(object, EventArgs)`) that call a state-changing method, directly or through a method of the page, when neither the page, its base classes nor a master page sets `ViewStateUserKey` and the page does not call `AntiForgery.Validate()`. Without a user-bound view state, an attacker can replay a postback captured from their own session against a logged-in victim.

## Recommendation

Perform state changes only in postback event handlers or `if (IsPostBack)` blocks, and set `ViewStateUserKey` to a per-user value (for example the session ID) in `Page_Init` or `OnInit`, ideally in a shared base page or master page. Alternatively, validate an anti-forgery token with `System.Web.Helpers.AntiForgery.Validate()`. Never perform state changes on `GET` requests.

## Example

The following page transfers money whenever the request contains the expected parameters, including on a cross-site `GET` request:

```csharp
protected void Page_Load(object sender, EventArgs e)
{
    var t = new MoneyTransfer();
    t.debitAccount = Request.Params["debitAccount"];
    t.creditAccount = Request.Params["creditAccount"];
    new Services().TransferBalance(t); // BAD
}
```

Binding the view state to the user and only acting on postbacks fixes the problem:

```csharp
protected override void OnInit(EventArgs e)
{
    base.OnInit(e);
    ViewStateUserKey = Session.SessionID;
}

protected void Page_Load(object sender, EventArgs e)
{
    if (IsPostBack)
    {
        new Services().TransferBalance(ReadTransferFromControls()); // GOOD
    }
}
```

The following checkout page places an order and charges the card in a postback handler, but nothing binds the view state to the user:

```csharp
protected void btnPlaceOrder_Click(object sender, EventArgs e)
{
    _creditCard.ChargeCard(order.Total); // BAD
    _orderRepository.CreateOrder(order);
}
```

Setting `ViewStateUserKey` in `OnInit`, in a shared base page, or in the master page, as shown above, fixes the problem.

## References

- OWASP: [Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
- Microsoft Learn: [Page.ViewStateUserKey Property](https://learn.microsoft.com/en-us/dotnet/api/system.web.ui.page.viewstateuserkey).
- Common Weakness Enumeration: [CWE-352](https://cwe.mitre.org/data/definitions/352.html).
