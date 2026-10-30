using System.Web.Mvc;
using ApiController = System.Web.Http.ApiController;
using ApiHttpConfiguration = System.Web.Http.HttpConfiguration;
using ApiHttpPost = System.Web.Http.HttpPostAttribute;
using ApiAuthorize = System.Web.Http.AuthorizeAttribute;

namespace Blog
{
    public class Startup
    {
        public void RegisterFilters(ApiHttpConfiguration configuration)
        {
            GlobalFilters.Filters.Add(new AuthorizeAttribute());
            configuration.Filters.Add(new ApiAuthorize());
        }
    }

    public class Comment
    {
        public int Id;
    }

    public class CommentsController : Controller
    {
        [HttpPost]
        public void Create(Comment comment) { }
    }

    public class CommentsApiController : ApiController
    {
        [ApiHttpPost]
        public void Create(Comment comment) { }
    }
}
