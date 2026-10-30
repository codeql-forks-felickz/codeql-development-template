// GOOD: authorization is required globally through an `AuthorizeFilter`, so controller actions
// without an `[Authorize]` attribute are still protected.
using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;

namespace Microsoft.AspNetCore.Mvc.Filters
{
    public class FilterCollection
    {
        public void Add(object filter) { }
        public void Insert(int index, object filter) { }
    }
}

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

    public abstract class ControllerBase { }

    public class MvcOptions
    {
        public Filters.FilterCollection Filters { get; } = new Filters.FilterCollection();
    }

    public abstract class Controller : ControllerBase
    {
        public IActionResult RedirectToAction(string action) => null;
    }
}

namespace Blog
{
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
        public IActionResult Create(Comment comment) // $ MISSING: Alert[cs/web/missing-authentication-state-changing-action]
        {
            Console.WriteLine(comment.Id);
            return RedirectToAction("Index");
        }
    }
}
