// Minimal stubs for types that are not available to the C# qltest extractor.

namespace System.Web
{
    public class HttpRequest
    {
        public System.Collections.Specialized.NameValueCollection Params => null;
        public System.Collections.Specialized.NameValueCollection Form => null;
        public string this[string key] => null;
    }
}

namespace System.Web.UI
{
    public class Page
    {
        public System.Web.HttpRequest Request => null;
    }
}

namespace System.Web.UI.WebControls
{
    public class TextBox
    {
        public string Text { get; set; }
    }
}

namespace System.Data.OleDb
{
    public sealed class OleDbConnection
    {
        public OleDbConnection() { }
        public OleDbConnection(string connectionString) { }
    }

    public sealed class OleDbCommand
    {
        public OleDbCommand(string cmdText, OleDbConnection connection) { }
    }

    public sealed class OleDbDataAdapter
    {
        public OleDbDataAdapter(string selectCommandText, OleDbConnection selectConnection) { }
        public OleDbDataAdapter(string selectCommandText, string selectConnectionString) { }
        public int Fill(System.Data.DataSet dataSet) => 0;
    }
}

namespace System.Data.Odbc
{
    public sealed class OdbcConnection
    {
        public OdbcConnection(string connectionString) { }
    }

    public sealed class OdbcDataAdapter
    {
        public OdbcDataAdapter(string selectCommandText, OdbcConnection selectConnection) { }
        public OdbcDataAdapter(string selectCommandText, string selectConnectionString) { }
        public int Fill(System.Data.DataSet dataSet) => 0;
    }
}

namespace MySql.Data.MySqlClient
{
    public sealed class MySqlConnection
    {
        public MySqlConnection(string connectionString) { }
    }

    public sealed class MySqlDataAdapter
    {
        public MySqlDataAdapter(string selectCommandText, MySqlConnection connection) { }
        public MySqlDataAdapter(string selectCommandText, string selectConnString) { }
        public int Fill(System.Data.DataSet dataSet) => 0;
    }
}
