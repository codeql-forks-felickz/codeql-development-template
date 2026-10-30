// Minimal stubs modelled on System.Web (ASP.NET Web Forms) public API signatures.
namespace System.Web
{
    public sealed class HttpRequest
    {
        public string this[string key] => throw null;
        public HttpValueCollection Params => throw null;
        public HttpValueCollection QueryString => throw null;
    }

    public class HttpValueCollection
    {
        public string this[string name] => throw null;
    }

    public sealed class HttpResponse
    {
        public string ContentType { get; set; }
        public void Write(string s) => throw null;
    }

    public sealed class HttpContext
    {
        public HttpRequest Request { get; }
        public HttpResponse Response => throw null;
    }

    public interface IHttpHandler
    {
        void ProcessRequest(HttpContext context);
        bool IsReusable { get; }
    }
}

namespace System.Web.UI
{
    public class Page
    {
        public System.Web.HttpRequest Request { get; }
    }
}
