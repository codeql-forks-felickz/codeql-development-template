using System;
using System.Web.Mvc;
using ApiAuthorize = System.Web.Http.AuthorizeAttribute;
using ApiController = System.Web.Http.ApiController;
using ApiHttpPost = System.Web.Http.HttpPostAttribute;

namespace Blog
{
    public class Comment
    {
        public int Id;
    }

    public class CommentsController : Controller
    {
        [HttpPost]
        public void Create(Comment comment) // $ Alert[cs/web/missing-authentication-state-changing-action]
        {
            Console.WriteLine(comment.Id);
        }

        [Authorize, HttpPost]
        public void Protected(Comment comment)
        {
            Console.WriteLine(comment.Id);
        }

    }

    public class CommentsApiController : ApiController
    {
        [ApiHttpPost]
        public void Create(Comment comment) // $ Alert[cs/web/missing-authentication-state-changing-action]
        {
            Console.WriteLine(comment.Id);
        }

        [ApiAuthorize, ApiHttpPost]
        public void Protected(Comment comment)
        {
            Console.WriteLine(comment.Id);
        }
    }

    public class LegacyAuthorizationController : LegacyBaseController
    {
        [HttpPost]
        public void Delete(Comment comment) // $ Alert[cs/web/missing-authentication-state-changing-action]
        {
            Console.WriteLine(comment.Id);
        }
    }

    public class LegacyBaseController : Controller
    {
        protected override void OnActionExecuting(ActionExecutingContext context)
        {
            if (!User.Identity.IsAuthenticated)
                throw new UnauthorizedAccessException();
        }
    }

    public class FilterFactory
    {
        public AuthorizeAttribute BuildFilter() => new AuthorizeAttribute();
    }
}
