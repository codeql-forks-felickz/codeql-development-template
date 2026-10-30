using System;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Microsoft.AspNetCore.Authorization
{
    public class AuthorizationPolicy { }

    public class AuthorizationOptions
    {
        public AuthorizationPolicy FallbackPolicy { get; set; }
        public AuthorizationPolicy DefaultPolicy { get; set; }
    }
}

namespace Microsoft.AspNetCore.Mvc
{
    public interface IActionResult { }
    public abstract class ControllerBase { }
    public abstract class Controller : ControllerBase { }
    public class HttpPostAttribute : Attribute { }
}

namespace Blog
{
    public class Startup
    {
        public void Configure(AuthorizationOptions options)
        {
            options.FallbackPolicy = options.DefaultPolicy;
        }
    }

    public class CommentsController : Controller
    {
        [HttpPost]
        public IActionResult Delete() { Console.WriteLine("delete"); return null; } // $ MISSING: Alert[cs/web/missing-authentication-state-changing-action]
    }
}
