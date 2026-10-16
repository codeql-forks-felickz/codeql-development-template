// GOOD: authorization is required globally through an `AuthorizeFilter`, so controller actions
// without an `[Authorize]` attribute are still protected.
using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;

namespace Microsoft.AspNetCore.Mvc.Authorization
{
    public class AuthorizeFilter
    {
        public AuthorizeFilter() { }
    }
}

namespace Microsoft.AspNetCore.Mvc
{
    public interface IActionResult { }

    public class HttpPostAttribute : Attribute { }

    public abstract class Controller
    {
        public IActionResult RedirectToAction(string action) => null;
    }
}

namespace Blog
{
    public class MvcOptions
    {
        public System.Collections.Generic.List<object> Filters = new System.Collections.Generic.List<object>();
    }

    public class Startup
    {
        public void ConfigureMvc(MvcOptions options)
        {
            options.Filters.Add(new AuthorizeFilter());
        }
    }

    public class Comment { public int Id; }

    public class CommentsController : Controller
    {
        [HttpPost]
        public IActionResult Create(Comment comment)
        {
            Console.WriteLine(comment.Id);
            return RedirectToAction("Index");
        }
    }
}
