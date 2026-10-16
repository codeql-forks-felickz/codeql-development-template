// Minimal stubs for types that are not available to the C# qltest extractor.

namespace Stubs
{
    // Shared `System.Data.IDbCommand` implementation for provider command stubs.
    public abstract class CommandBase : System.Data.IDbCommand
    {
        public string CommandText { get; set; }
        public int CommandTimeout { get; set; }
        public System.Data.CommandType CommandType { get; set; }
        public System.Data.IDbConnection Connection { get; set; }
        public System.Data.IDataParameterCollection Parameters => null;
        public System.Data.IDbTransaction Transaction { get; set; }
        public System.Data.UpdateRowSource UpdatedRowSource { get; set; }
        public void Cancel() { }
        public System.Data.IDbDataParameter CreateParameter() => null;
        public int ExecuteNonQuery() => 0;
        public System.Data.IDataReader ExecuteReader() => null;
        public System.Data.IDataReader ExecuteReader(System.Data.CommandBehavior behavior) => null;
        public object ExecuteScalar() => null;
        public void Prepare() { }
        public void Dispose() { }
    }
}

namespace System.Web
{
    public class HttpRequest
    {
        public System.Collections.Specialized.NameValueCollection Params => null;
        public System.Collections.Specialized.NameValueCollection Form => null;
        public HttpCookieCollection Cookies => null;
        public string this[string key] => null;
    }

    public sealed class HttpCookieCollection
    {
        public HttpCookie this[string name] => null;
    }

    public sealed class HttpCookie
    {
        public string Value { get; set; }
    }

    public sealed class HttpContext
    {
        public HttpRequest Request => null;
    }

    public interface IHttpHandler
    {
        void ProcessRequest(HttpContext context);
    }
}

namespace System.Web.Services
{
    public class WebService { }

    [System.AttributeUsage(System.AttributeTargets.Method)]
    public sealed class WebMethodAttribute : System.Attribute { }
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

    public sealed class OleDbCommand : Stubs.CommandBase
    {
        public OleDbCommand() { }
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

    public sealed class MySqlCommand : Stubs.CommandBase
    {
        public MySqlCommand(string cmdText, MySqlConnection connection) { }
    }

    public sealed class MySqlDataAdapter
    {
        public MySqlDataAdapter(string selectCommandText, MySqlConnection connection) { }
        public MySqlDataAdapter(string selectCommandText, string selectConnString) { }
        public int Fill(System.Data.DataSet dataSet) => 0;
    }

    public sealed class MySqlHelper
    {
        public static object ExecuteScalar(string connectionString, string commandText) => null;
    }
}

namespace Mono.Data.Sqlite
{
    public sealed class SqliteConnection
    {
        public SqliteConnection(string connectionString) { }
    }

    public sealed class SqliteCommand : Stubs.CommandBase
    {
        public SqliteCommand(string sql, SqliteConnection connection) { }
    }

    public sealed class SqliteDataAdapter
    {
        public SqliteDataAdapter(string commandText, SqliteConnection connection) { }
        public SqliteDataAdapter(string commandText, string connectionString) { }
        public int Fill(System.Data.DataSet dataSet) => 0;
    }
}
