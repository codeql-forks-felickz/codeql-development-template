// Minimal stubs for the parts of System.Web used by the tests.
namespace System.Web
{
    public class HttpRequest
    {
        public System.Collections.Specialized.NameValueCollection QueryString => null;
        public System.Collections.Specialized.NameValueCollection Params => null;
        public System.Collections.Specialized.NameValueCollection Headers => null;
        public string FilePath => null;
        public string this[string key] => null;
        public string MapPath(string virtualPath) => null;
    }

    public class HttpResponse
    {
        public void AddHeader(string name, string value) { }
        public void BinaryWrite(byte[] buffer) { }
        public string ContentType { get; set; }
        public void AppendHeader(string name, string value) { }
        public void End() { }
        public void TransmitFile(string filename) { }
        public void TransmitFile(string filename, long offset, long length) { }
        public void WriteFile(string filename) { }
        public void WriteFile(string filename, bool readIntoMemory) { }
        public void WriteFile(string filename, long offset, long size) { }
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
