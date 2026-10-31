using ApiAuthorize = System.Web.Http.AuthorizeAttribute;
using ApiController = System.Web.Http.ApiController;
using ApiHttpConfiguration = System.Web.Http.HttpConfiguration;
using ApiHttpPost = System.Web.Http.HttpPostAttribute;

namespace Blog
{
    public class Startup
    {
        public void RegisterFilters(ApiHttpConfiguration configuration)
        {
            configuration.Filters.Add(new ApiAuthorize());
        }
    }

    public class Comment
    {
        public int Id;
    }

    public class CommentsApiController : ApiController
    {
        [ApiHttpPost]
        public void Create(Comment comment) { }
    }
}
