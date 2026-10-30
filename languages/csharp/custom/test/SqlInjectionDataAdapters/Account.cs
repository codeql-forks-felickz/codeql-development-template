using System.Data;
using System.Data.Odbc;
using System.Data.OleDb;

namespace Altoro
{
    // Web Forms page: `Request.Params` concatenated into `OleDbDataAdapter` /
    // `OdbcDataAdapter` select text.
    public partial class Account : System.Web.UI.Page
    {
        protected void Page_Load(object sender, System.EventArgs e)
        {
            string userAccount = Request.Params["listAccounts"]; // $ Source
            GetBalance(userAccount);
            GetBalanceOdbc(userAccount);
            GetBalanceSafe(userAccount);
        }

        private string GetBalance(string accountNumber)
        {
            OleDbConnection myConnection = new OleDbConnection();
            myConnection.Open();
            string query = "SELECT SUM(amount) AS Balance FROM transactions WHERE accountid=" + accountNumber;
            OleDbDataAdapter myBalance = new OleDbDataAdapter(query, myConnection); // $ Alert
            DataSet ds = new DataSet();
            myBalance.Fill(ds, "balance");
            OleDbDataAdapter byConnString = new OleDbDataAdapter(query, "Provider=SQLOLEDB"); // $ Alert
            byConnString.Fill(ds, "balance");
            myConnection.Close();
            return "";
        }

        private string GetBalanceOdbc(string accountNumber)
        {
            OdbcDataAdapter adapter = new OdbcDataAdapter("SELECT * FROM transactions WHERE accountid=" + accountNumber, new OdbcConnection("DSN=bank")); // $ Alert
            adapter.Fill(new DataSet());
            return "";
        }

        // Constant SQL text is safe; user data never reaches the select text.
        private string GetBalanceSafe(string accountNumber)
        {
            OleDbDataAdapter adapter = new OleDbDataAdapter("SELECT SUM(amount) AS Balance FROM transactions", new OleDbConnection());
            adapter.Fill(new DataSet());
            return accountNumber;
        }
    }
}
