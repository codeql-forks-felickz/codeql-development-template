// Minimal stubs modelled on ADO.NET provider public API signatures
// (System.Data.SqlClient, System.Data.OleDb, System.Data.Odbc,
// MySql.Data.MySqlClient and Mono.Data.Sqlite).
using System;
using System.Data;
using System.Data.Common;

namespace System.Data.SqlClient
{
    public sealed class SqlConnection : IDisposable
    {
        public SqlConnection(string connectionString) => throw null;
        public void Open() => throw null;
        public void Dispose() => throw null;
    }

    public sealed class SqlCommand : IDisposable
    {
        public SqlCommand(string cmdText) => throw null;
        public SqlCommand(string cmdText, SqlConnection connection) => throw null;
        public SqlConnection Connection { get; set; }
        public IDataReader ExecuteReader() => throw null;
        public void Dispose() => throw null;
    }
}

namespace System.Data.OleDb
{
    public sealed class OleDbConnection
    {
        public string ConnectionString { get; set; }
        public void Open() => throw null;
        public void Close() => throw null;
    }

    public sealed class OleDbDataAdapter : DbDataAdapter
    {
        public OleDbDataAdapter() => throw null;
        public OleDbDataAdapter(string selectCommandText, OleDbConnection selectConnection) => throw null;
        public OleDbDataAdapter(string selectCommandText, string selectConnectionString) => throw null;
    }
}

namespace System.Data.Odbc
{
    public sealed class OdbcConnection
    {
        public OdbcConnection(string connectionString) => throw null;
    }

    public sealed class OdbcDataAdapter : DbDataAdapter
    {
        public OdbcDataAdapter() => throw null;
        public OdbcDataAdapter(string selectCommandText, OdbcConnection selectConnection) => throw null;
        public OdbcDataAdapter(string selectCommandText, string selectConnectionString) => throw null;
    }
}

namespace MySql.Data.MySqlClient
{
    public sealed class MySqlConnection : IDisposable
    {
        public MySqlConnection(string connectionString) => throw null;
        public void Dispose() => throw null;
    }

    public sealed class MySqlDataAdapter : DbDataAdapter
    {
        public MySqlDataAdapter() => throw null;
        public MySqlDataAdapter(string selectCommandText, MySqlConnection connection) => throw null;
        public MySqlDataAdapter(string selectCommandText, string selectConnString) => throw null;
    }
}

namespace Mono.Data.Sqlite
{
    public sealed class SqliteConnection : IDisposable
    {
        public SqliteConnection(string connectionString) => throw null;
        public void Open() => throw null;
        public void Dispose() => throw null;
    }

    public sealed class SqliteCommand : IDbCommand
    {
        public SqliteCommand(string commandText, SqliteConnection connection) => throw null;
        public string CommandText { get; set; }
        public int ExecuteNonQuery() => throw null;
        public IDataReader ExecuteReader() => throw null;
        public void Dispose() => throw null;
    }

    public sealed class SqliteDataAdapter : DbDataAdapter
    {
        public SqliteDataAdapter() => throw null;
        public SqliteDataAdapter(string commandText, SqliteConnection connection) => throw null;
        public SqliteDataAdapter(string commandText, string connectionString) => throw null;
    }
}
