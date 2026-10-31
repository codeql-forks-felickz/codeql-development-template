// Minimal stubs for System.Web (ASP.NET Framework), which is not part of .NET (Core).
using System.Collections.Specialized;

namespace System.Collections.Specialized
{
    public class NameValueCollection
    {
        public string this[string name] { get => null; set { } }
        public void Add(string name, string value) { }
        public void Set(string name, string value) { }
        public string Get(string name) => this[name];
    }
}

namespace System.Web
{
    public class HttpRequest
    {
        public NameValueCollection QueryString => null;
        public NameValueCollection Form => null;
        public NameValueCollection Params => null;
        public string this[string key] => null;
    }

    public class HttpResponse
    {
        public NameValueCollection Headers => null;
        public HttpCookieCollection Cookies => null;
        public string RedirectLocation { get; set; }
        public void AddHeader(string name, string value) { }
        public void AppendHeader(string name, string value) { }
        public void Redirect(string url) { }
        public void Redirect(string url, bool endResponse) { }
    }

    public abstract class HttpResponseBase
    {
        public virtual NameValueCollection Headers => null;
        public virtual HttpCookieCollection Cookies => null;
        public virtual string RedirectLocation { get; set; }
        public virtual void AddHeader(string name, string value) { }
        public virtual void AppendHeader(string name, string value) { }
        public virtual void Redirect(string url) { }
        public virtual void Redirect(string url, bool endResponse) { }
    }

    public class HttpCookie
    {
        public HttpCookie(string name, string value) { }
        public string Value { get; set; }
    }

    public class HttpCookieCollection
    {
        public HttpCookie this[string name] => null;
        public void Add(HttpCookie cookie) { }
    }

    public class HttpServerUtility
    {
        public string HtmlEncode(string s) => null;
        public string UrlEncode(string s) => null;
    }

    public sealed class HttpUtility
    {
        public static string HtmlEncode(string s) => null;
        public static string UrlEncode(string s) => null;
        public static string UrlEncode(string s, System.Text.Encoding e) => null;
    }

    public interface IHttpHandler
    {
        void ProcessRequest(HttpContext context);
    }

    public sealed class HttpContext
    {
        public HttpRequest Request => null;
        public HttpResponse Response => null;
    }
}

namespace System.Web.UI
{
    public class Page
    {
        public HttpRequest Request => null;
        public HttpResponse Response => null;
        public HttpServerUtility Server => null;
    }
}
