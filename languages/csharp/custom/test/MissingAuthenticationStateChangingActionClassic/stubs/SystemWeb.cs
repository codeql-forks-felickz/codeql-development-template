using System;
using System.Security.Principal;

namespace System.Web.Mvc
{
    public class ActionExecutingContext { }
    public class AuthorizeAttribute : Attribute { }
    public class HttpPostAttribute : Attribute { }
    public class NonActionAttribute : Attribute { }

    public class GlobalFilterCollection
    {
        public void Add(object filter) { }
    }

    public static class GlobalFilters
    {
        public static GlobalFilterCollection Filters { get; } = new GlobalFilterCollection();
    }

    public class Controller
    {
        public IPrincipal User { get; set; }
        protected virtual void OnActionExecuting(ActionExecutingContext context) { }
    }
}

namespace System.Web.Http
{
    public class AuthorizeAttribute : Attribute { }
    public class HttpPostAttribute : Attribute { }
    public class NonActionAttribute : Attribute { }

    public class ApiController
    {
        protected virtual void OnActionExecuting(object context) { }
    }
}
