using System;
using System.Data;
using System.Data.OleDb;
using System.Data.SqlClient;

namespace Bank
{
    // Account page that trusts a client-side `amUserId` cookie and an
    // `listAccounts` request parameter to decide which records to show.
    public class Account : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (!Convert.ToBoolean(Session["authenticated"]))
            {
                return;
            }

            string thisUser = Request.Cookies["amUserId"].Value; // $ Source
            GetAccounts(thisUser);

            string userAccount = Request.Params["listAccounts"]; // $ Source
            GetBalance(userAccount);

            // Not an identifier: not a direct object reference.
            string sortOrder = Request.Params["sort"];
            GetSorted(sortOrder);
        }

        private void GetAccounts(string userId)
        {
            OleDbConnection myConnection = new OleDbConnection();
            string query = "SELECT accountid, acct_type From accounts WHERE userid = " + userId;
            OleDbDataAdapter myAccount = new OleDbDataAdapter(query, myConnection); // $ Alert
            myAccount.Fill(new DataSet(), "accounts");
        }

        private void GetBalance(string accountNumber)
        {
            OleDbConnection myConnection = new OleDbConnection();
            string query = "SELECT SUM(amount) AS Balance FROM transactions WHERE accountid=" + accountNumber;
            OleDbDataAdapter myBalance = new OleDbDataAdapter(query, myConnection); // $ Alert
            myBalance.Fill(new DataSet(), "balance");
        }

        private void GetSorted(string column)
        {
            OleDbConnection myConnection = new OleDbConnection();
            OleDbDataAdapter adapter = new OleDbDataAdapter("SELECT * FROM rates ORDER BY " + column, myConnection);
            adapter.Fill(new DataSet(), "rates");
        }
    }

    // Safe counterpart: the user is taken from the server-side session and the
    // requested account is checked against the accounts that user owns.
    public class SafeAccount : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string thisUser = (string)Session["userId"];
            string userAccount = Request.Params["listAccounts"];
            if (!UserOwnsAccount(thisUser, userAccount))
            {
                return;
            }
            OleDbConnection myConnection = new OleDbConnection();
            OleDbDataAdapter adapter = new OleDbDataAdapter("SELECT * FROM transactions WHERE accountid=" + userAccount, myConnection);
            adapter.Fill(new DataSet(), "balance");
        }

        private bool UserOwnsAccount(string user, string account) => false;
    }

    public class MoneyTransfer
    {
        public string debitAccount;
        public string creditAccount;
        public double transferAmount;
    }

    public class Services
    {
        public string TransferBalance(MoneyTransfer t)
        {
            SqlConnection connection = new SqlConnection();
            SqlCommand command = new SqlCommand("UPDATE accounts SET balance = balance - @amount WHERE accountid = @debit", connection);
            command.Parameters.AddWithValue("@debit", t.debitAccount); // $ Alert
            command.Parameters.AddWithValue("@credit", t.creditAccount); // $ Alert
            command.Parameters.AddWithValue("@amount", t.transferAmount);
            command.ExecuteNonQuery();
            return "ok";
        }
    }

    // Transfer page that moves money out of any `debitAccount` supplied by the client.
    public class Transfer : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string debitAccount = this.Request.Params["debitAccount"]; // $ Source
            string creditAccount = this.Request.Params["creditAccount"]; // $ Source
            string transferAmount = this.Request.Params["transferAmount"];

            MoneyTransfer myTransaction = new MoneyTransfer();
            myTransaction.debitAccount = debitAccount;
            myTransaction.creditAccount = creditAccount;
            myTransaction.transferAmount = Convert.ToDouble(transferAmount);
            new Services().TransferBalance(myTransaction);
        }
    }

    // Safe counterpart: the debit account is verified to belong to the
    // authenticated principal before the transfer is executed.
    public class SafeTransfer : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string debitAccount = this.Request.Params["debitAccount"];
            if (!AccountBelongsTo(debitAccount, User.Identity.Name))
            {
                return;
            }
            MoneyTransfer myTransaction = new MoneyTransfer();
            myTransaction.debitAccount = debitAccount;
            new Services().TransferBalance(myTransaction);
        }

        private bool AccountBelongsTo(string account, string user) => false;
    }
}
