// Minimal stubs for the parts of System.Web used by the tests.
namespace System.Web
{
    public class HttpRequest
    {
        public System.Collections.Specialized.NameValueCollection QueryString => null;
        public System.Collections.Specialized.NameValueCollection Params => null;
        public System.Collections.Specialized.NameValueCollection Headers => null;
        public string FilePath => null;
        public string MapPath(string virtualPath) => null;
    }

    public class HttpResponse
    {
        public void AddHeader(string name, string value) { }
        public void BinaryWrite(byte[] buffer) { }
    }

    public class HttpServerUtility
    {
        public string MapPath(string path) => null;
    }
}

namespace System.Web.UI
{
    public class Control { }

    public class TemplateControl : Control { }

    public class Page : TemplateControl
    {
        public System.Web.HttpRequest Request => null;
        public System.Web.HttpResponse Response => null;
        public System.Web.HttpServerUtility Server => null;
        public string MapPath(string virtualPath) => null;
    }
}
