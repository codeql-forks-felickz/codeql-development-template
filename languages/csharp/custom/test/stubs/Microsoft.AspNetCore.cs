// Minimal stubs for ASP.NET Core MVC controllers and minimal API routing.

namespace Microsoft.AspNetCore.Mvc
{
    public interface IActionResult { }

    public class OkResult : IActionResult { }

    public abstract class ControllerBase
    {
        public virtual OkResult Ok() => throw null;
    }

    [System.AttributeUsage(System.AttributeTargets.Class)]
    public class ApiControllerAttribute : System.Attribute { }

    [System.AttributeUsage(System.AttributeTargets.Parameter)]
    public class FromBodyAttribute : System.Attribute { }

    [System.AttributeUsage(System.AttributeTargets.Method)]
    public class HttpPostAttribute : System.Attribute
    {
        public HttpPostAttribute(string template) => throw null;
    }
}

namespace Microsoft.AspNetCore.Routing
{
    public interface IEndpointRouteBuilder { }
}

namespace Microsoft.AspNetCore.Builder
{
    public static class EndpointRouteBuilderExtensions
    {
        public static object MapPost(this Microsoft.AspNetCore.Routing.IEndpointRouteBuilder endpoints, string pattern, System.Delegate handler) => throw null;
    }
}
