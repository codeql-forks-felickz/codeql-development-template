// Sanitized reproduction: a Web Forms page that performs a money transfer from raw request
// parameters on any request, including GET, without CSRF protection.
using System;
using System.Web.UI;

namespace Bank
{
    public class MoneyTransfer
    {
        public string debitAccount;
        public string creditAccount;
        public double transferAmount;
    }

    public class Services
    {
        public string TransferBalance(MoneyTransfer t) => "ok";
        public void TransferFunds(string from, string to, double amount) { }
        public string GetBalance(string account) => "0";
    }

    public partial class Transfer : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (!Convert.ToBoolean(Session["authenticated"]))
                return;

            if (Request.Params.Count > 3)
            {
                string debitAccount = Request.Params["debitAccount"];
                string creditAccount = Request.Params["creditAccount"];
                string transferAmount = Request.Params["transferAmount"];

                if (!string.IsNullOrEmpty(debitAccount) && !string.IsNullOrEmpty(creditAccount))
                {
                    var t = new MoneyTransfer();
                    t.debitAccount = debitAccount;
                    t.creditAccount = creditAccount;
                    t.transferAmount = Convert.ToDouble(transferAmount);
                    // BAD: state change driven by request parameters, reachable by a cross-site GET.
                    Response.Write(new Services().TransferBalance(t)); // $ Alert[cs/web/webforms-request-forgery]
                }
            }
        }
    }

    public partial class QuickTransfer : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // BAD: the query string is never protected by ViewState validation.
            DoTransfer(Request.QueryString["from"], Request.QueryString["to"]);
        }

        private void DoTransfer(string from, string to)
        {
            new Services().TransferFunds(from, to, 100); // $ Alert[cs/web/webforms-request-forgery]
        }
    }

    public partial class Balance : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // GOOD: read-only.
            Response.Write(new Services().GetBalance(Request.QueryString["account"]));
        }
    }

    public partial class ValidatedTransfer : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // GOOD: explicit anti-forgery token validation.
            System.Web.Helpers.AntiForgery.Validate();
            new Services().TransferFunds(Request.Form["from"], Request.Form["to"], 1);
        }
    }

    public class SecurePageBase : Page
    {
        protected override void OnInit(EventArgs e)
        {
            base.OnInit(e);
            ViewStateUserKey = Session.SessionID;
        }
    }

    public partial class PostBackTransfer : SecurePageBase
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // GOOD: only on postback, and the page binds ViewState to the user's session.
            if (IsPostBack)
            {
                new Services().TransferFunds(Request.Form["from"], Request.Form["to"], 1);
            }
        }
    }

    public partial class GetTransferOnSecureBase : SecurePageBase
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // BAD: `ViewStateUserKey` does not protect requests that are not postbacks.
            new Services().TransferFunds(Request.QueryString["from"], Request.QueryString["to"], 1); // $ Alert[cs/web/webforms-request-forgery]
        }
    }
}
