// Minimal stubs for the ASP.NET Core MVC types used by this test.
namespace Microsoft.AspNetCore.Mvc
{
    public abstract class ControllerBase { }

    [System.AttributeUsage(System.AttributeTargets.Class)]
    public class ApiControllerAttribute : System.Attribute { }

    public class RouteAttribute : System.Attribute
    {
        public RouteAttribute(string template) { }
    }

    public class HttpGetAttribute : System.Attribute
    {
        public HttpGetAttribute(string template) { }
    }
}
