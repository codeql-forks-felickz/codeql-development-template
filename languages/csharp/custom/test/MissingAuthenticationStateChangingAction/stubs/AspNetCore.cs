// Minimal stubs of the ASP.NET Core MVC and authorization APIs used by the tests.
using System;
using System.IO;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class AuthorizeAttribute : Attribute
    {
        public AuthorizeAttribute() { }
        public AuthorizeAttribute(string policy) { Policy = policy; }
        public string Policy { get; set; }
        public string Roles { get; set; }
    }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
    public class AllowAnonymousAttribute : Attribute { }
}

namespace Microsoft.AspNetCore.Http
{
    public interface IFormFile
    {
        string FileName { get; }
        void CopyTo(Stream target);
    }
}

namespace Microsoft.AspNetCore.Mvc
{
    public interface IActionResult { }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
    public class RouteAttribute : Attribute { public RouteAttribute(string template) { } }

    [AttributeUsage(AttributeTargets.Class)]
    public class ApiControllerAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Method)]
    public class ActionNameAttribute : Attribute { public ActionNameAttribute(string name) { } }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class ValidateAntiForgeryTokenAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Parameter)]
    public class BindAttribute : Attribute { public BindAttribute(params string[] include) { } }

    [AttributeUsage(AttributeTargets.Parameter)]
    public class FromBodyAttribute : Attribute { }

    public abstract class HttpMethodAttribute : Attribute
    {
        protected HttpMethodAttribute() { }
        protected HttpMethodAttribute(string template) { }
        public string Name { get; set; }
    }

    public class HttpGetAttribute : HttpMethodAttribute { public HttpGetAttribute() { } public HttpGetAttribute(string template) : base(template) { } }
    public class HttpPostAttribute : HttpMethodAttribute { public HttpPostAttribute() { } public HttpPostAttribute(string template) : base(template) { } }
    public class HttpPutAttribute : HttpMethodAttribute { public HttpPutAttribute() { } public HttpPutAttribute(string template) : base(template) { } }
    public class HttpDeleteAttribute : HttpMethodAttribute { public HttpDeleteAttribute() { } public HttpDeleteAttribute(string template) : base(template) { } }

    public abstract class ControllerBase
    {
        public ClaimsPrincipal User { get; }
        public IActionResult Ok(object value) => null;
        public IActionResult NotFound() => null;
        public IActionResult Unauthorized() => null;
        public IActionResult RedirectToAction(string action) => null;
    }

    public abstract class Controller : ControllerBase
    {
        public IActionResult View(object model = null) => null;
    }
}
