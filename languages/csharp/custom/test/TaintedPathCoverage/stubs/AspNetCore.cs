// Minimal stubs for the parts of ASP.NET Core used by the tests.
namespace Microsoft.AspNetCore.Http
{
    public interface IFormFile
    {
        string ContentType { get; }
        string FileName { get; }
        string Name { get; }
        long Length { get; }
        void CopyTo(System.IO.Stream target);
        System.IO.Stream OpenReadStream();
    }

    public interface IFormFileCollection : System.Collections.Generic.IReadOnlyList<IFormFile> { }

    public interface IFormCollection
    {
        IFormFileCollection Files { get; }
    }

    public abstract class HttpRequest
    {
        public abstract IFormCollection Form { get; set; }
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
    [System.AttributeUsage(System.AttributeTargets.Class)]
    public class ApiControllerAttribute : System.Attribute { }

    [System.AttributeUsage(System.AttributeTargets.Class)]
    public class RouteAttribute : System.Attribute
    {
        public RouteAttribute(string template) { }
    }

    [System.AttributeUsage(System.AttributeTargets.Class)]
    public class ControllerAttribute : System.Attribute { }

    [System.AttributeUsage(System.AttributeTargets.Method)]
    public class HttpPostAttribute : System.Attribute
    {
        public string Name { get; set; }
    }

    [System.AttributeUsage(System.AttributeTargets.Method)]
    public class HttpGetAttribute : System.Attribute
    {
        public HttpGetAttribute(string template) { }
    }

    public interface IActionResult { }

    public class OkResult : IActionResult { }

    [Controller]
    public abstract class ControllerBase { }
}

namespace Microsoft.AspNetCore.Mvc.RazorPages
{
    public abstract class PageModel
    {
        public Microsoft.AspNetCore.Http.HttpRequest Request { get; }
    }
}
