// Minimal stubs of the ASP.NET Web Forms (System.Web) APIs used by the tests.
using System.Collections.Specialized;

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
        public NameValueCollection Params { get; }
        public NameValueCollection QueryString { get; }
        public NameValueCollection Form { get; }
        public HttpCookieCollection Cookies { get; }
        public string HttpMethod { get; }
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
        public string SessionID { get; }
    }
}

namespace System.Web.Helpers
{
    public static class AntiForgery
    {
        public static void Validate() { }
    }
}

namespace System.Web.UI
{
    public class Control
    {
        protected virtual void OnInit(EventArgs e) { }
    }

    public class Page : Control
    {
        public HttpRequest Request { get; }
        public HttpResponse Response { get; }
        public System.Web.SessionState.HttpSessionState Session { get; }
        public bool IsPostBack { get; }
        public string ViewStateUserKey { get; set; }
    }
}
