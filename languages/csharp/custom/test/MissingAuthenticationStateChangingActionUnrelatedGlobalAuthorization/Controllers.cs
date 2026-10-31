using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;

namespace Microsoft.AspNetCore.Mvc.Authorization
{
    public class AuthorizeFilter { }
}

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
    public class EndpointConventionBuilder
    {
        public EndpointConventionBuilder RequireAuthorization() => this;
    }

    public static class EndpointRouteBuilderExtensions
    {
        public static EndpointConventionBuilder MapGet(EndpointRouteBuilder builder, string pattern) => null;
    }

}

namespace Blog
{
    public class Comment { public int Id; }

    public class Startup
    {
        public void Configure()
        {
            var filters = new List<object>();
            filters.Add(new Microsoft.AspNetCore.Mvc.Authorization.AuthorizeFilter());

            var endpoints = new Microsoft.AspNetCore.Builder.EndpointRouteBuilder();
            Microsoft.AspNetCore.Builder.EndpointRouteBuilderExtensions
                .MapGet(endpoints, "/health")
                .RequireAuthorization();
        }
    }

    public class CommentsController : Controller
    {
        [HttpPost]
        public IActionResult Create(Comment comment) { Console.WriteLine(comment.Id); return null; } // $ Alert[cs/web/missing-authentication-state-changing-action]
    }
}
