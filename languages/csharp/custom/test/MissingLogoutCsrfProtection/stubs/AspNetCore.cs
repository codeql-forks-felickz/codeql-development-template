using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class AuthorizeAttribute : Attribute { }
}

namespace Microsoft.AspNetCore.Mvc
{
    public class Controller
    {
        public Microsoft.AspNetCore.Http.HttpContext HttpContext { get; }
    }

    public interface IActionResult { }

    [AttributeUsage(AttributeTargets.Method)]
    public class HttpPostAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class ValidateAntiForgeryTokenAttribute : Attribute { }
}

namespace Microsoft.AspNetCore.Http
{
    public class HttpContext { }
}

namespace Microsoft.AspNetCore.Authentication
{
    public static class AuthenticationHttpContextExtensions
    {
        public static Task SignOutAsync(this Microsoft.AspNetCore.Http.HttpContext context) => null;
    }
}
