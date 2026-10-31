// Minimal ASP.NET Core stubs so the test database can be extracted without the
// Microsoft.AspNetCore.App shared framework.
using System;

namespace Microsoft.Extensions.Primitives
{
    public struct StringValues
    {
        public override string ToString() => null;
    }
}

namespace Microsoft.AspNetCore.Http
{
    public interface IQueryCollection
    {
        Microsoft.Extensions.Primitives.StringValues this[string key] { get; }
    }

    public abstract class HttpRequest
    {
        public abstract IQueryCollection Query { get; set; }
    }

    public abstract class HttpContext
    {
        public abstract HttpRequest Request { get; }
    }
}

namespace Microsoft.AspNetCore.Mvc
{
    public interface IActionResult { }

    public abstract class ControllerBase
    {
        public Microsoft.AspNetCore.Http.HttpContext HttpContext => null;

        public IActionResult Ok(object value) => null;
    }

    public abstract class Controller : ControllerBase { }

    [AttributeUsage(AttributeTargets.Class)]
    public class ApiControllerAttribute : Attribute { }

    public class RouteAttribute : Attribute
    {
        public RouteAttribute(string template) { }
    }

    public class HttpGetAttribute : Attribute
    {
        public HttpGetAttribute() { }

        public HttpGetAttribute(string template) { }

        public string Name { get; set; }
    }

    public class HttpPostAttribute : Attribute
    {
        public HttpPostAttribute() { }

        public HttpPostAttribute(string template) { }

        public string Name { get; set; }
    }
}
