// Minimal stubs for System.Web (ASP.NET Framework) and ASP.NET Core, which the
// qltest extractor does not reference.
using System.Collections.Specialized;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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
        public NameValueCollection QueryString => null;
    }

    public class HttpResponse
    {
        public int StatusCode { get; set; }
        public string StatusDescription { get; set; }
    }

    public abstract class HttpResponseBase
    {
        public virtual int StatusCode { get; set; }
        public virtual string StatusDescription { get; set; }
    }

    public sealed class HttpUtility
    {
        public static string HtmlEncode(string s) => null;
    }
}

namespace Microsoft.AspNetCore.Http
{
    public abstract class HttpResponse
    {
        public abstract string ContentType { get; set; }
    }

    public abstract class HttpContext
    {
        public abstract HttpResponse Response { get; }
    }

    public static class HttpResponseWritingExtensions
    {
        public static Task WriteAsync(this HttpResponse response, string text, CancellationToken cancellationToken = default) => null;
        public static Task WriteAsync(this HttpResponse response, string text, Encoding encoding, CancellationToken cancellationToken = default) => null;
    }
}

namespace Microsoft.AspNetCore.Mvc
{
    public class ControllerContext
    {
        public Microsoft.AspNetCore.Http.HttpContext HttpContext { get; set; }
    }

    public abstract class ControllerBase
    {
        public ControllerContext ControllerContext { get; set; }
    }

    [System.AttributeUsage(System.AttributeTargets.Class)]
    public class ControllerAttribute : System.Attribute { }

    [System.AttributeUsage(System.AttributeTargets.Class)]
    public class ApiControllerAttribute : ControllerAttribute { }

    public class RouteAttribute : System.Attribute
    {
        public RouteAttribute(string template) { }
    }
}
