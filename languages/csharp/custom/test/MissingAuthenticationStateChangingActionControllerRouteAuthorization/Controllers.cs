using System;
using Microsoft.AspNetCore.Mvc;

namespace Microsoft.AspNetCore.Mvc
{
    public interface IActionResult { }
    public abstract class ControllerBase { }
    public abstract class Controller : ControllerBase { }
    public class HttpPostAttribute : Attribute { }
}

namespace Microsoft.AspNetCore.Builder
{
    public class EndpointRouteBuilder { }
    public class ControllerActionEndpointConventionBuilder
    {
        public ControllerActionEndpointConventionBuilder RequireAuthorization() => this;
    }

    public static class ControllerEndpointRouteBuilderExtensions
    {
        public static ControllerActionEndpointConventionBuilder MapControllers(EndpointRouteBuilder builder) => null;
    }

}

namespace Blog
{
    public class Startup
    {
        public void Configure()
        {
            var endpoints = new Microsoft.AspNetCore.Builder.EndpointRouteBuilder();
            Microsoft.AspNetCore.Builder.ControllerEndpointRouteBuilderExtensions
                .MapControllers(endpoints)
                .RequireAuthorization();
        }
    }

    public class CommentsController : Controller
    {
        [HttpPost]
        public IActionResult Delete() { Console.WriteLine("delete"); return null; } // $ MISSING: Alert[cs/web/missing-authentication-state-changing-action]
    }
}
