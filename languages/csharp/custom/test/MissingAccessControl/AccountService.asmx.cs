using System.Web.Mvc;
using System.Web.Services;

namespace Bank.WebServices
{
    [WebService(Namespace = "http://example.com/")]
    public class AccountService : WebService
    {
        // BAD: state-changing web method without any authorization check.
        [WebMethod]
        public string TransferBalance(long from, long to, double amount) // $ Alert
        {
            Withdraw(from, amount);
            Deposit(to, amount);
            return "OK";
        }

        // BAD: edit operation exposed as a web method without authorization.
        [WebMethod]
        public void DeleteAccount(long accountId) // $ Alert
        {
            Remove(accountId);
        }

        // GOOD: checks that the caller is authenticated.
        [WebMethod]
        public string TransferBalanceChecked(long from, long to, double amount)
        {
            if (!Context.User.Identity.IsAuthenticated)
                return "Unauthorized";
            Withdraw(from, amount);
            Deposit(to, amount);
            return "OK";
        }

        // GOOD: checks the caller's role.
        [WebMethod]
        public void DeleteAccountChecked(long accountId)
        {
            if (Context.User.IsInRole("Admin"))
                Remove(accountId);
        }

        // GOOD: protected by an authorization attribute.
        [WebMethod]
        [Authorize]
        public string TransferBalanceAuthorized(long from, long to, double amount)
        {
            Withdraw(from, amount);
            Deposit(to, amount);
            return "OK";
        }

        // Not flagged: read-only operation, the query only targets sensitive (state-changing / admin) actions.
        [WebMethod]
        public long[] GetUserAccounts(long userId)
        {
            return new long[] { userId };
        }

        // GOOD: not a web method, so not remotely invocable.
        public void TransferInternal(long from, long to, double amount)
        {
            Withdraw(from, amount);
            Deposit(to, amount);
        }

        // GOOD: empty web method.
        [WebMethod]
        public void TransferNothing() { }

        private void Withdraw(long account, double amount) { }

        private void Deposit(long account, double amount) { }

        private void Remove(long account) { }
    }

    [Authorize]
    public class AdminService : WebService
    {
        // GOOD: the declaring class is protected by an authorization attribute.
        [WebMethod]
        public void DeleteUser(long userId)
        {
            System.Console.WriteLine(userId);
        }
    }

    public class TransfersPage : System.Web.UI.Page
    {
        // BAD: ASP.NET page method (static [WebMethod]) without authorization.
        [WebMethod]
        public static void TransferFunds(long from, long to, double amount) // $ Alert
        {
            System.Console.WriteLine(from + to + amount);
        }
    }
}
