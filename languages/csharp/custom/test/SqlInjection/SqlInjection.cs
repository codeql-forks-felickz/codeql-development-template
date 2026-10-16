using System.Data;
using System.Data.Odbc;
using System.Data.OleDb;
using System.Web.UI;
using System.Web.UI.WebControls;
using MySql.Data.MySqlClient;

namespace SqlInjectionTests
{
    // Web Forms login handler that concatenates request parameters into OleDb SQL text.
    public class OleDbLogin : Page
    {
        public void Page_Load()
        {
            string uname = Request.Params["uid"]; // $ Source
            string passwd = Request.Params["passw"]; // $ Source
            ValidateUser(uname, passwd);
        }

        private bool ValidateUser(string userName, string password)
        {
            var connection = new OleDbConnection();
            string query = "SELECT * FROM users WHERE username = '" + userName + "' AND password = '" + password + "'";
            var adapter = new OleDbDataAdapter(query, connection); // $ Alert
            var ds = new DataSet();
            adapter.Fill(ds);
            return ds.Tables.Count != 0;
        }

        public void ConnectionStringOverload()
        {
            string query = "SELECT * FROM users WHERE username = '" + Request.Form["user"] + "'"; // $ Source
            new OleDbDataAdapter(query, "Provider=Microsoft.Jet.OLEDB.4.0"); // $ Alert
        }

        public void StockOleDbCommand(OleDbConnection conn)
        {
            // Already covered by the stock `System.Data.OleDb.OleDbCommand` sink model.
            var cmd = new OleDbCommand("SELECT * FROM users WHERE name='" + Request["user"] + "'", conn); // $ Alert
        }

        public void ConstantQuery(OleDbConnection conn)
        {
            // Not tainted: constant SQL text.
            new OleDbDataAdapter("SELECT * FROM users", conn);
        }
    }

    public interface IDbProvider
    {
        bool IsValidCustomerLogin(string email, string password);
    }

    // MySQL provider branch reached through an interface call from a login page.
    public class MySqlDbProvider : IDbProvider
    {
        private readonly string connectionString = "";

        public bool IsValidCustomerLogin(string email, string password)
        {
            string sql = "select * from CustomerLogin where email = '" + email +
                "' and password = '" + password + "';";
            var connection = new MySqlConnection(connectionString);
            var da = new MySqlDataAdapter(sql, connection); // $ Alert
            var ds = new DataSet();
            da.Fill(ds);
            return ds.Tables.Count != 0;
        }
    }

    public class CustomerLogin : Page
    {
        protected TextBox txtUserName;
        protected TextBox txtPassword;
        private IDbProvider du = new MySqlDbProvider();

        public void ButtonLogOn_Click()
        {
            string email = txtUserName.Text; // $ Source
            string pwd = txtPassword.Text; // $ Source
            du.IsValidCustomerLogin(email, pwd);
        }

        public void MySqlConnectionStringOverload()
        {
            new MySqlDataAdapter("select * from t where id = " + txtUserName.Text, ""); // $ Alert
        }
    }

    public class OdbcLogin : Page
    {
        public void Search(OdbcConnection conn)
        {
            string query = "SELECT * FROM items WHERE name = '" + Request.Params["q"] + "'"; // $ Source
            new OdbcDataAdapter(query, conn); // $ Alert
            new OdbcDataAdapter(query, "DSN=items"); // $ Alert
        }
    }
}
