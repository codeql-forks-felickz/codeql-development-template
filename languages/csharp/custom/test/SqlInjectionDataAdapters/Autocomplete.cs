using System.Data;
using System.Web;
using MySql.Data.MySqlClient;
using Mono.Data.Sqlite;

namespace WebGoat
{
    public interface IDbProvider
    {
        DataSet GetCustomerEmails(string email);
    }

    public class MySqlDbProvider : IDbProvider
    {
        private string _connectionString = "";

        public DataSet GetCustomerEmails(string email)
        {
            string sql = "select email from CustomerLogin where email like '" + email + "%'";
            using (MySqlConnection connection = new MySqlConnection(_connectionString))
            {
                MySqlDataAdapter da = new MySqlDataAdapter(sql, connection); // $ Alert
                DataSet ds = new DataSet();
                da.Fill(ds);
                return ds;
            }
        }
    }

    public class SqliteDbProvider : IDbProvider
    {
        private string _connectionString = "";

        public DataSet GetCustomerEmails(string email)
        {
            string sql = "select email from CustomerLogin where email like '" + email + "%'";
            using (SqliteConnection connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                SqliteDataAdapter da = new SqliteDataAdapter(sql, connection); // $ Alert
                DataSet ds = new DataSet();
                da.Fill(ds);
                return ds;
            }
        }
    }

    public static class Settings
    {
        public static IDbProvider CurrentDbProvider { get; set; }

        public static void Init(string provider)
        {
            CurrentDbProvider = provider == "MySql" ? (IDbProvider)new MySqlDbProvider() : new SqliteDbProvider();
        }
    }

    // Generic handler: `context.Request["query"]` flows through an interface
    // call into the provider implementations above.
    public class Autocomplete : IHttpHandler
    {
        private IDbProvider du = Settings.CurrentDbProvider;

        public void ProcessRequest(HttpContext context)
        {
            string query = context.Request["query"]; // $ Source
            DataSet ds = du.GetCustomerEmails(query);
            context.Response.Write("");
        }

        public bool IsReusable => false;
    }
}
