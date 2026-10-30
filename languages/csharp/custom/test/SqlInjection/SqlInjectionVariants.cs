using System;
using System.Data;
using System.Data.OleDb;
using System.Web;
using System.Web.Services;
using System.Web.UI;
using System.Web.UI.WebControls;
using Mono.Data.Sqlite;
using MySql.Data.MySqlClient;

namespace SqlInjectionVariants
{
    // Cookie value passed to a helper that concatenates it into OleDb SQL text.
    public class AccountsPage : Page
    {
        public void Page_Load()
        {
            string userId = Request.Cookies["userId"].Value; // $ Source
            GetAccounts(userId);
        }

        private DataTable GetAccounts(string userId)
        {
            var connection = new OleDbConnection();
            string query = "SELECT accountid, acct_type FROM accounts WHERE userid = " + userId;
            var adapter = new OleDbDataAdapter(query, connection); // $ Alert
            var ds = new DataSet();
            adapter.Fill(ds);
            return ds.Tables[0];
        }
    }

    // ASMX web service: `[WebMethod]` parameters, including public fields of parameter types, are remote input.
    public class BankService : WebService
    {
        public class MoneyTransfer
        {
            public string debitAccount;
            public string creditAccount;
            public double transferAmount;
        }

        [WebMethod]
        public bool IsValidUser(string userId) // $ Source
        {
            string query = "SELECT * FROM users WHERE userid = " + userId;
            var adapter = new OleDbDataAdapter(query, new OleDbConnection()); // $ Alert
            var ds = new DataSet();
            adapter.Fill(ds);
            return ds.Tables.Count != 0;
        }

        [WebMethod]
        public bool TransferBalance(MoneyTransfer transfer) // $ Source
        {
            var command = new OleDbCommand();
            command.CommandText = "SELECT count(*) FROM accounts WHERE accountid=" + transfer.debitAccount; // $ Alert
            command.ExecuteScalar();
            command.CommandText = "INSERT INTO transactions (accountid, amount) VALUES (" + transfer.creditAccount + ", " + transfer.transferAmount + ")"; // $ Alert
            command.ExecuteNonQuery();
            return true;
        }
    }

    // Web Forms page that forwards request parameters to the web service class directly.
    public class TransferPage : Page
    {
        public void Page_Load()
        {
            var transfer = new BankService.MoneyTransfer();
            transfer.debitAccount = Request.Params["debitAccount"]; // $ Source
            transfer.creditAccount = Request.Params["creditAccount"]; // $ Source
            new BankService().TransferBalance(transfer);
        }
    }

    // Control whose property is set by a page, then read in a framework-invoked `Render` override.
    // `cs/sql-injection` cannot connect the setter call on one instance to the `this` read in an
    // uncalled override, so this remains a known false negative.
    public class LineItemTable : Page
    {
        private string myAccount;

        public string accountNumber
        {
            get { return myAccount; }
            set { myAccount = value; }
        }

        protected DataTable GetLineItems()
        {
            string query = "SELECT description, amount FROM transactions WHERE accountid = " + myAccount;
            var adapter = new OleDbDataAdapter(query, new OleDbConnection()); // $ MISSING: Alert
            var ds = new DataSet();
            adapter.Fill(ds);
            return ds.Tables[0];
        }

        protected virtual void Render()
        {
            GetLineItems();
        }
    }

    public class AccountPage : Page
    {
        protected LineItemTable Credit;

        public void Page_Load()
        {
            Credit.accountNumber = Request.Params["listAccounts"];
        }
    }

    public interface IDataProvider
    {
        DataSet GetCustomerDetails(string customerNumber);
        string GetCustomerEmail(string customerNumber);
        string AddComment(string productCode, string email, string comment);
        string[] GetSecurityQuestionAndAnswer(string email);
        DataSet GetProductDetails(string productCode);
        DataSet GetCustomerEmails(string email);
        string GetEmailByCustomerNumber(string num);
    }

    public class MySqlProvider : IDataProvider
    {
        private readonly string connectionString = "";

        public DataSet GetCustomerDetails(string customerNumber)
        {
            string sql = "select * from Customers where customerNumber = " + customerNumber;
            var da = new MySqlDataAdapter(sql, new MySqlConnection(connectionString)); // $ Alert
            var ds = new DataSet();
            da.Fill(ds);
            return ds;
        }

        public string GetCustomerEmail(string customerNumber)
        {
            string sql = "select email from CustomerLogin where customerNumber = " + customerNumber;
            var command = new MySqlCommand(sql, new MySqlConnection(connectionString)); // $ Alert
            return command.ExecuteScalar() as string;
        }

        public string AddComment(string productCode, string email, string comment)
        {
            string sql = "insert into Comments(productCode, email, comment) values ('" + productCode + "','" + email + "','" + comment + "');";
            var command = new MySqlCommand(sql, new MySqlConnection(connectionString)); // $ Alert
            command.ExecuteNonQuery();
            return null;
        }

        public string[] GetSecurityQuestionAndAnswer(string email)
        {
            string sql = "select SecurityQuestion, SecurityAnswer from CustomerLogin where email = '" + email + "';";
            var da = new MySqlDataAdapter(sql, new MySqlConnection(connectionString)); // $ Alert
            var ds = new DataSet();
            da.Fill(ds);
            return new string[0];
        }

        public DataSet GetProductDetails(string productCode)
        {
            string sql = "select * from Products where productCode = '" + productCode + "'";
            var da = new MySqlDataAdapter(sql, new MySqlConnection(connectionString)); // $ Alert
            var ds = new DataSet();
            da.Fill(ds);
            return ds;
        }

        public DataSet GetCustomerEmails(string email)
        {
            string sql = "select email from CustomerLogin where email like '" + email + "%'";
            var da = new MySqlDataAdapter(sql, new MySqlConnection(connectionString)); // $ Alert
            var ds = new DataSet();
            da.Fill(ds);
            return ds;
        }

        public string GetEmailByCustomerNumber(string num)
        {
            // Already covered by the stock `MySqlHelper` sink models.
            return (string)MySqlHelper.ExecuteScalar(connectionString, "select email from CustomerLogin where customerNumber = " + num); // $ Alert
        }
    }

    public class SqliteProvider : IDataProvider
    {
        private readonly string connectionString = "";

        public DataSet GetCustomerDetails(string customerNumber)
        {
            string sql = "select * from Customers where customerNumber = " + customerNumber;
            var da = new SqliteDataAdapter(sql, new SqliteConnection(connectionString)); // $ Alert
            var ds = new DataSet();
            da.Fill(ds);
            return ds;
        }

        public string GetCustomerEmail(string customerNumber)
        {
            string sql = "select email from CustomerLogin where customerNumber = " + customerNumber;
            var command = new SqliteCommand(sql, new SqliteConnection(connectionString)); // $ Alert
            return command.ExecuteScalar() as string;
        }

        public string AddComment(string productCode, string email, string comment)
        {
            string sql = "insert into Comments(productCode, email, comment) values ('" + productCode + "','" + email + "','" + comment + "');";
            var command = new SqliteCommand(sql, new SqliteConnection(connectionString)); // $ Alert
            command.ExecuteNonQuery();
            return null;
        }

        public string[] GetSecurityQuestionAndAnswer(string email)
        {
            string sql = "select SecurityQuestion, SecurityAnswer from CustomerLogin where email = '" + email + "';";
            var da = new SqliteDataAdapter(sql, connectionString); // $ Alert
            var ds = new DataSet();
            da.Fill(ds);
            return new string[0];
        }

        public DataSet GetProductDetails(string productCode)
        {
            string sql = "select * from Products where productCode = '" + productCode + "'";
            var da = new SqliteDataAdapter(sql, new SqliteConnection(connectionString)); // $ Alert
            var ds = new DataSet();
            da.Fill(ds);
            return ds;
        }

        public DataSet GetCustomerEmails(string email)
        {
            string sql = "select email from CustomerLogin where email like '" + email + "%'";
            var da = new SqliteDataAdapter(sql, new SqliteConnection(connectionString)); // $ Alert
            var ds = new DataSet();
            da.Fill(ds);
            return ds;
        }

        public string GetEmailByCustomerNumber(string num)
        {
            // Not tainted: constant SQL text.
            new SqliteDataAdapter("select email from CustomerLogin", connectionString);
            return null;
        }
    }

    public class MainPage : Page
    {
        private IDataProvider du;

        public void Page_Load()
        {
            string customerNumber = Request.Cookies["customerNumber"].Value; // $ Source
            du.GetCustomerDetails(customerNumber);
            du.GetCustomerEmail(customerNumber);
            du.GetEmailByCustomerNumber(customerNumber);
        }
    }

    public class ProductDetailsPage : Page
    {
        private IDataProvider du;
        protected TextBox txtEmail;
        protected TextBox txtComment;

        public void Page_Load()
        {
            du.GetProductDetails(Request["productNumber"]); // $ Source
        }

        public void ButtonSave_Click()
        {
            du.AddComment("code", txtEmail.Text, txtComment.Text); // $ Source
        }
    }

    public class ForgotPasswordPage : Page
    {
        private IDataProvider du;
        protected TextBox txtEmail;

        public void ButtonCheckEmail_Click()
        {
            du.GetSecurityQuestionAndAnswer(txtEmail.Text); // $ Source
        }
    }

    public class Autocomplete : IHttpHandler
    {
        private IDataProvider du;

        public void ProcessRequest(HttpContext context)
        {
            string query = context.Request["query"]; // $ Source
            du.GetCustomerEmails(query);
        }
    }
}
