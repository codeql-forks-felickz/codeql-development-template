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

    [Controller]
    public abstract class ControllerBase { }
}
