// Minimal stubs for System.Web (ASP.NET Framework), which is not part of .NET (Core).
namespace System.Web
{
    using System.Collections.Specialized;

    public class HttpRequest
    {
        public NameValueCollection QueryString => null;
        public NameValueCollection Params => null;
        public NameValueCollection Form => null;
    }

    public class HttpResponse
    {
        public void Write(string s) { }
    }
}
