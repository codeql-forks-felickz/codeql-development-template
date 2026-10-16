// Minimal ASP.NET Core MVC stubs.
using System;

namespace Microsoft.AspNetCore.Mvc
{
    public interface IActionResult { }

    public class ContentResult : IActionResult
    {
        public string Content { get; set; }
        public string ContentType { get; set; }
        public int? StatusCode { get; set; }
    }

    public abstract class ControllerBase
    {
        public virtual ContentResult Content(string content) => null;
        public virtual ContentResult Content(string content, string contentType) => null;
        public virtual ContentResult Content(string content, string contentType, System.Text.Encoding contentEncoding) => null;
    }

    [AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
    public class ControllerAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Assembly, AllowMultiple = false, Inherited = true)]
    public class ApiControllerAttribute : ControllerAttribute { }

    public class RouteAttribute : Attribute
    {
        public RouteAttribute(string template) { }
    }

    public class HttpGetAttribute : Attribute
    {
        public string Name { get; set; }
    }
}

namespace System.Net
{
    public static class WebUtility
    {
        public static string HtmlEncode(string value) => null;
    }
}
