// Minimal stubs for the framework types used by the IdorAccessControl tests.

namespace System.Web
{
    public class HttpCookie
    {
        public string Value { get; set; }
    }

    public class HttpCookieCollection
    {
        public HttpCookie this[string name] => null;
    }

    public class HttpRequest
    {
        public System.Collections.Specialized.NameValueCollection Params => null;
        public System.Collections.Specialized.NameValueCollection QueryString => null;
        public HttpCookieCollection Cookies => null;
        public string this[string key] => null;
    }

    public class HttpResponse
    {
        public void Write(string s) { }
    }
}

namespace System.Web.SessionState
{
    public class HttpSessionState
    {
        public object this[string name] { get => null; set { } }
    }
}

namespace System.Web.UI
{
    public class Page
    {
        public System.Web.HttpRequest Request => null;
        public System.Web.HttpResponse Response => null;
        public System.Web.SessionState.HttpSessionState Session => null;
        public System.Security.Principal.IPrincipal User => null;
    }
}

namespace System.Data.SqlClient
{
    public class SqlConnection
    {
        public void Open() { }
    }

    public class SqlTransaction { }

    public class SqlParameter
    {
        public SqlParameter(string parameterName, object value) { }
        public SqlParameter(string parameterName, System.Data.SqlDbType dbType, int size) { }
        public object Value { get; set; }
    }

    public class SqlParameterCollection
    {
        public SqlParameter Add(SqlParameter value) => value;
        public SqlParameter AddWithValue(string parameterName, object value) => null;
    }

    public class SqlCommand : System.IDisposable
    {
        public SqlCommand(string cmdText, SqlConnection connection) { }
        public void Dispose() { }
        public string CommandText { get; set; }
        public SqlParameterCollection Parameters => null;
        public int ExecuteNonQuery() => 0;
    }
}

namespace System.Data.OleDb
{
    public class OleDbConnection
    {
        public void Open() { }
    }

    public class OleDbDataAdapter
    {
        public OleDbDataAdapter(string selectCommandText, OleDbConnection selectConnection) { }
        public int Fill(System.Data.DataSet dataSet, string srcTable) => 0;
    }
}

namespace Microsoft.AspNetCore.Mvc
{
    public interface IActionResult { }

    public abstract class ControllerBase
    {
        public System.Security.Claims.ClaimsPrincipal User => null;
        public IActionResult Ok(object value) => null;
        public IActionResult NotFound() => null;
        public IActionResult Forbid() => null;
    }

    public abstract class Controller : ControllerBase { }

    public class RouteAttribute : System.Attribute
    {
        public RouteAttribute(string template) { }
    }

    public class HttpGetAttribute : System.Attribute
    {
        public HttpGetAttribute() { }
        public HttpGetAttribute(string template) { }
    }

    public class HttpPutAttribute : System.Attribute
    {
        public HttpPutAttribute(string template) { }
    }

    public class HttpDeleteAttribute : System.Attribute
    {
        public HttpDeleteAttribute(string template) { }
    }

    public class FromBodyAttribute : System.Attribute { }
}

namespace Microsoft.AspNetCore.Authorization
{
    public class AuthorizeAttribute : System.Attribute
    {
        public AuthorizeAttribute() { }
        public string Roles { get; set; }
    }
}

namespace Microsoft.EntityFrameworkCore
{
    public class DbSet<TEntity> : System.Linq.IQueryable<TEntity> where TEntity : class
    {
        public System.Type ElementType => null;
        public System.Linq.Expressions.Expression Expression => null;
        public System.Linq.IQueryProvider Provider => null;
        public System.Collections.Generic.IEnumerator<TEntity> GetEnumerator() => null;
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => null;
        public virtual TEntity Find(params object[] keyValues) => null;
        public virtual void Update(TEntity entity) { }
        public virtual void Remove(TEntity entity) { }
    }

    public class DbContext
    {
        public int SaveChanges() => 0;
    }
}
