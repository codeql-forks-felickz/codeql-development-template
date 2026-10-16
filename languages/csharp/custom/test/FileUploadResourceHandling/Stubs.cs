// Minimal framework stubs for the test database.

namespace System.Web
{
    public class HttpRequest
    {
        public System.Collections.Specialized.NameValueCollection QueryString => null;
        public System.Collections.Specialized.NameValueCollection Params => null;
    }

    public class HttpResponse { }

    public class HttpServerUtility
    {
        public string MapPath(string path) => null;
    }

    public class HttpPostedFile
    {
        public string FileName => null;
        public void SaveAs(string filename) { }
    }
}

namespace System.Web.UI
{
    public class Page
    {
        public System.Web.HttpServerUtility Server => null;
    }
}

namespace System.Web.UI.WebControls
{
    public class FileUpload
    {
        public bool HasFile => false;
        public string FileName => null;
        public System.Web.HttpPostedFile PostedFile => null;
        public void SaveAs(string filename) { }
    }
}

namespace System.Data.SqlClient
{
    public class SqlConnection : System.IDisposable
    {
        public SqlConnection() { }
        public SqlConnection(string connectionString) { }
        public string ConnectionString { get; set; }
        public void ChangeDatabase(string database) { }
        public void Open() { }
        public void Dispose() { }
    }

    public class SqlConnectionStringBuilder
    {
        public string DataSource { get; set; }
        public string UserID { get; set; }
        public string ConnectionString { get; set; }
    }
}

namespace Microsoft.AspNetCore.Http
{
    public interface IFormFile
    {
        string FileName { get; }
        void CopyTo(System.IO.Stream target);
        System.Threading.Tasks.Task CopyToAsync(System.IO.Stream target, System.Threading.CancellationToken cancellationToken = default);
    }
}

namespace Microsoft.AspNetCore.Hosting
{
    public interface IWebHostEnvironment
    {
        string WebRootPath { get; set; }
    }
}

namespace Microsoft.AspNetCore.Mvc
{
    public class ControllerBase { }

    public class Controller : ControllerBase { }

    public class HttpPostAttribute : System.Attribute { }
}
