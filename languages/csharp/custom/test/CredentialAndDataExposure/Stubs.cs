// Minimal stubs of third-party / framework APIs used by the test cases.

namespace System.Web
{
    public class HttpCookie
    {
        public HttpCookie(string name) { }
        public HttpCookie(string name, string value) { }
        public string Value { get; set; }
        public string this[string key] { get { return null; } set { } }
        public System.DateTime Expires { get; set; }
    }

    public class HttpCookieCollection
    {
        public void Add(HttpCookie cookie) { }
        public HttpCookie this[string name] { get { return null; } }
    }

    public class HttpResponse
    {
        public void Write(string s) { }
        public HttpCookieCollection Cookies { get { return null; } }
    }

    public class HttpRequest
    {
        public System.Collections.Specialized.NameValueCollection Params { get { return null; } }
        public System.Collections.Specialized.NameValueCollection Form { get { return null; } }
    }
}

namespace System.Web.UI
{
    public class Control { }

    public class Page : Control
    {
        public System.Web.HttpRequest Request { get { return null; } }
        public System.Web.HttpResponse Response { get { return null; } }
        public bool IsPostBack { get { return false; } }
    }
}

namespace System.Web.UI.WebControls
{
    public enum TextBoxMode { SingleLine, MultiLine, Password }

    public class WebControl : System.Web.UI.Control { }

    public class TextBox : WebControl
    {
        public virtual string Text { get; set; }
        public virtual TextBoxMode TextMode { get; set; }
    }

    public class Label : WebControl
    {
        public virtual string Text { get; set; }
    }
}

namespace Microsoft.Extensions.Logging
{
    public interface ILogger { }

    public interface ILogger<out TCategoryName> : ILogger { }

    public static class LoggerExtensions
    {
        public static void LogInformation(this ILogger logger, string message, params object[] args) { }
    }
}

namespace Microsoft.EntityFrameworkCore
{
    public class DbContext
    {
        public virtual object Add<TEntity>(TEntity entity) where TEntity : class { return null; }
        public virtual object Update<TEntity>(TEntity entity) where TEntity : class { return null; }
        public virtual int SaveChanges() { return 0; }
        public virtual System.Threading.Tasks.Task<int> SaveChangesAsync() { return null; }
    }

    public abstract class DbSet<TEntity> where TEntity : class
    {
        public virtual object Add(TEntity entity) { return null; }
        public virtual object Update(TEntity entity) { return null; }
    }
}

namespace Microsoft.AspNetCore.Mvc
{
    public interface IActionResult { }

    public abstract class ControllerBase { }

    public abstract class Controller : ControllerBase
    {
        public virtual IActionResult View(object model) { return null; }
        public virtual IActionResult RedirectToAction(string actionName) { return null; }
    }

    public class HttpPostAttribute : System.Attribute { }

    public class BindAttribute : System.Attribute
    {
        public BindAttribute(params string[] include) { }
    }
}

namespace Microsoft.AspNetCore.Mvc.ViewFeatures
{
    public class ViewDataDictionary<TModel> { }

    public class ModelExpression { }

    public interface IModelExpressionProvider
    {
        ModelExpression CreateModelExpression<TModel, TValue>(
            ViewDataDictionary<TModel> viewData,
            System.Linq.Expressions.Expression<System.Func<TModel, TValue>> expression);
    }
}

namespace Microsoft.AspNetCore.Html
{
    public interface IHtmlContent { }
}

namespace Microsoft.AspNetCore.Mvc.Rendering
{
    public interface IHtmlHelper<TModel>
    {
        string DisplayNameFor<TResult>(System.Linq.Expressions.Expression<System.Func<TModel, TResult>> expression);
        Microsoft.AspNetCore.Html.IHtmlContent TextBoxFor<TResult>(System.Linq.Expressions.Expression<System.Func<TModel, TResult>> expression, string format, object htmlAttributes);
        Microsoft.AspNetCore.Html.IHtmlContent PasswordFor<TResult>(System.Linq.Expressions.Expression<System.Func<TModel, TResult>> expression, object htmlAttributes);
    }

    public static class HtmlHelperDisplayExtensions
    {
        public static Microsoft.AspNetCore.Html.IHtmlContent DisplayFor<TModel, TResult>(
            this IHtmlHelper<TModel> htmlHelper,
            System.Linq.Expressions.Expression<System.Func<TModel, TResult>> expression)
        { return null; }
    }
}

namespace Microsoft.AspNetCore.Razor.TagHelpers
{
    public enum HtmlAttributeValueStyle { DoubleQuotes, SingleQuotes, NoQuotes, Minimized }

    public class TagHelperAttribute
    {
        public TagHelperAttribute(string name, object value, HtmlAttributeValueStyle valueStyle) { }
        public object Value { get { return null; } }
    }
}

namespace Microsoft.AspNetCore.Mvc.TagHelpers
{
    public class InputTagHelper
    {
        public Microsoft.AspNetCore.Mvc.ViewFeatures.ModelExpression For { get; set; }
        public string InputTypeName { get; set; }
    }

    public class LabelTagHelper
    {
        public Microsoft.AspNetCore.Mvc.ViewFeatures.ModelExpression For { get; set; }
    }
}

namespace Microsoft.AspNetCore.Mvc.Razor
{
    public abstract class RazorPageBase
    {
        public abstract System.Threading.Tasks.Task ExecuteAsync();
        public virtual void Write(object value) { }
        public virtual void WriteLiteral(object value) { }
    }

    public abstract class RazorPage : RazorPageBase { }

    public abstract class RazorPage<TModel> : RazorPage
    {
        public TModel Model { get { return default(TModel); } }
        public Microsoft.AspNetCore.Mvc.ViewFeatures.ViewDataDictionary<TModel> ViewData { get { return null; } }
    }
}

namespace Microsoft.IdentityModel.Tokens
{
    public abstract class SecurityKey { }

    public class SymmetricSecurityKey : SecurityKey
    {
        public SymmetricSecurityKey(byte[] key) { }
    }
}

namespace Mono.Data.Sqlite
{
    public class SqliteConnection : System.Data.IDbConnection
    {
        public SqliteConnection(string connectionString) { }
        public string ConnectionString { get; set; }
        public int ConnectionTimeout { get { return 0; } }
        public string Database { get { return null; } }
        public System.Data.ConnectionState State { get { return default(System.Data.ConnectionState); } }
        public System.Data.IDbTransaction BeginTransaction() { return null; }
        public System.Data.IDbTransaction BeginTransaction(System.Data.IsolationLevel il) { return null; }
        public void ChangeDatabase(string databaseName) { }
        public void Close() { }
        public System.Data.IDbCommand CreateCommand() { return null; }
        public void Open() { }
        public void Dispose() { }
    }

    public class SqliteCommand : System.Data.IDbCommand
    {
        public SqliteCommand(string commandText, SqliteConnection connection) { }
        public string CommandText { get; set; }
        public int CommandTimeout { get; set; }
        public System.Data.CommandType CommandType { get; set; }
        public System.Data.IDbConnection Connection { get; set; }
        public System.Data.IDataParameterCollection Parameters { get { return null; } }
        public System.Data.IDbTransaction Transaction { get; set; }
        public System.Data.UpdateRowSource UpdatedRowSource { get; set; }
        public void Cancel() { }
        public System.Data.IDbDataParameter CreateParameter() { return null; }
        public int ExecuteNonQuery() { return 0; }
        public System.Data.IDataReader ExecuteReader() { return null; }
        public System.Data.IDataReader ExecuteReader(System.Data.CommandBehavior behavior) { return null; }
        public object ExecuteScalar() { return null; }
        public void Prepare() { }
        public void Dispose() { }
    }
}
