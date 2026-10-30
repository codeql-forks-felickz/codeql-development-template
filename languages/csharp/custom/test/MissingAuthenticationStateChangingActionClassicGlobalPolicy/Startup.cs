using System.Web.Mvc;

namespace Blog
{
    public class Startup
    {
        public void RegisterFilters()
        {
            GlobalFilters.Filters.Add(new AuthorizeAttribute());
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

}
