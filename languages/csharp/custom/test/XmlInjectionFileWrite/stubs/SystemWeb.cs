// Minimal stubs for the .NET Framework `System.Web` types used by this test.
namespace System.Web
{
    public class HttpRequest
    {
        public System.Collections.Specialized.NameValueCollection QueryString => null;
    }

    public class HttpServerUtility
    {
        public string MapPath(string path) => null;
    }
}

namespace System.Web.UI
{
    public class Page
    {
        public System.Web.HttpRequest Request => null;
        public System.Web.HttpServerUtility Server => null;
    }
}
