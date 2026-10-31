// Minimal stubs of the ASP.NET Core MVC and authorization APIs used by the tests.
using System;
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
        public string AuthenticationSchemes { get; set; }
    }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
    public class AllowAnonymousAttribute : Attribute { }

    public class AuthorizationResult
    {
        public bool Succeeded { get; }
    }

    public interface IAuthorizationService
    {
        Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object resource, string policyName);
    }
}

namespace Microsoft.AspNetCore.Mvc
{
    public interface IActionResult { }

    public class ObjectResult : IActionResult { }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
    public class RouteAttribute : Attribute { public RouteAttribute(string template) { } }

    [AttributeUsage(AttributeTargets.Class)]
    public class ApiControllerAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Parameter)]
    public class FromBodyAttribute : Attribute { }

    public abstract class HttpMethodAttribute : Attribute
    {
        protected HttpMethodAttribute() { }
        protected HttpMethodAttribute(string template) { }
    }

    public class HttpGetAttribute : HttpMethodAttribute { public HttpGetAttribute() { } public HttpGetAttribute(string template) : base(template) { } }
    public class HttpPostAttribute : HttpMethodAttribute { public HttpPostAttribute() { } public HttpPostAttribute(string template) : base(template) { } }
    public class HttpPutAttribute : HttpMethodAttribute { public HttpPutAttribute() { } public HttpPutAttribute(string template) : base(template) { } }
    public class HttpPatchAttribute : HttpMethodAttribute { public HttpPatchAttribute() { } public HttpPatchAttribute(string template) : base(template) { } }
    public class HttpDeleteAttribute : HttpMethodAttribute { public HttpDeleteAttribute() { } public HttpDeleteAttribute(string template) : base(template) { } }

    public abstract class ControllerBase
    {
        public ClaimsPrincipal User { get; }
        public IActionResult Ok(object value) => null;
        public IActionResult NotFound() => null;
        public IActionResult Forbid() => null;
    }

    public abstract class Controller : ControllerBase { }
}
