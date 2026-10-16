// Minimal framework stubs (System.Web, System.Data, EF Core, ASP.NET Core MVC).
using System.Collections;
using System.Collections.Generic;

namespace System.Collections.Specialized
{
    public class NameValueCollection
    {
        public string this[string name] { get => null; set { } }
    }
}

namespace System.Web
{
    public class HttpRequest
    {
        public System.Collections.Specialized.NameValueCollection QueryString => null;
        public System.Collections.Specialized.NameValueCollection Params => null;
    }

    public sealed class HttpUtility
    {
        public static string HtmlEncode(string s) => null;
    }
}

namespace System.Web.UI
{
    public class Control { }

    public class Page : Control
    {
        public System.Web.HttpRequest Request => null;
    }
}

namespace System.Web.UI.WebControls
{
    public class WebControl : System.Web.UI.Control { }

    public class Label : WebControl
    {
        public virtual string Text { get; set; }
    }

    public class TextBox : WebControl
    {
        public virtual string Text { get; set; }
    }

    public class Literal : System.Web.UI.Control
    {
        public string Text { get; set; }
    }
}

namespace System.Web.UI.HtmlControls
{
    public class HtmlGenericControl : System.Web.UI.Control
    {
        public string InnerHtml { get; set; }
        public string InnerText { get; set; }
    }
}

namespace System.Data
{
    public interface IDataRecord
    {
        object this[string name] { get; }
        string GetString(int i);
    }

    public class DataColumn { }

    public class DataRow
    {
        public DataRow[] GetChildRows(string relationName) => null;
        public object this[string columnName] { get => null; set { } }
        public object this[int columnIndex] { get => null; set { } }
        public object[] ItemArray { get => null; set { } }
    }

    public static class DataRowExtensions
    {
        public static T Field<T>(this DataRow row, string columnName) => default(T);
    }

    public class DataRowCollection : IEnumerable
    {
        public IEnumerator GetEnumerator() => null;
    }

    public class DataTable
    {
        public DataRowCollection Rows => null;
    }

    public class DataTableCollection
    {
        public DataTable this[int index] => null;
        public DataTable this[string name] => null;
    }

    public class DataSet
    {
        public DataTableCollection Tables => null;
    }
}

namespace System.Data.Common
{
    public abstract class DbDataReader : System.Data.IDataRecord
    {
        public abstract object this[string name] { get; }
        public abstract string GetString(int i);
        public abstract bool Read();
    }

    public abstract class DbCommand
    {
        public string CommandText { get; set; }
        public DbDataReader ExecuteReader() => null;
        public int ExecuteNonQuery() => 0;
    }

    public abstract class DbDataAdapter
    {
        public int Fill(System.Data.DataSet dataSet) => 0;
    }
}

namespace Microsoft.EntityFrameworkCore
{
    public class DbContext
    {
        public int SaveChanges() => 0;
    }

    public abstract class DbSet<TEntity> : IEnumerable<TEntity> where TEntity : class
    {
        public virtual void Add(TEntity entity) { }
        public IEnumerator<TEntity> GetEnumerator() => null;
        IEnumerator IEnumerable.GetEnumerator() => null;
    }
}

namespace System.Data.Entity
{
    public class DbContext : IDisposable
    {
        public int SaveChanges() => 0;
        public void Dispose() { }
    }

    public abstract class DbSet<TEntity> : IEnumerable<TEntity> where TEntity : class
    {
        public virtual TEntity Add(TEntity entity) => entity;
        public IEnumerator<TEntity> GetEnumerator() => null;
        IEnumerator IEnumerable.GetEnumerator() => null;
    }
}

namespace Microsoft.AspNetCore.Html
{
    public interface IHtmlContent { }
}

namespace Microsoft.AspNetCore.Mvc.Rendering
{
    public interface IHtmlHelper
    {
        Microsoft.AspNetCore.Html.IHtmlContent Raw(string value);
        Microsoft.AspNetCore.Html.IHtmlContent Raw(object value);
        string Encode(string value);
    }
}
