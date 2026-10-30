// The ASP.NET Core assemblies are intentionally not referenced by this test
// (there is no Web SDK project file), mirroring a `build-mode: none` analysis
// of loose source files. `ControllerBase`, `Controller` and the routing
// attributes are therefore unresolved types.
using Microsoft.AspNetCore.Mvc;
using System.Xml;

namespace Bookstore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class BookSearch : ControllerBase
    {
        [HttpGet("{author}")]
        public void ByAuthor(string author) // $ Source
        {
            XmlDocument doc = new XmlDocument();
            doc.Load("bookstore.xml");
            XmlNode root = doc.DocumentElement;
            XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace("bk", "urn:newbooks-schema");

            XmlNode node = root.SelectSingleNode(
                "descendant::bk:book[bk:author/bk:last-name='" + author + "']", nsmgr); // $ Alert
        }

        [HttpGet("title/{title}")]
        public void ByTitle(string title) // $ Source
        {
            XmlDocument doc = new XmlDocument();
            doc.Load("bookstore.xml");
            XmlNodeList nodes = doc.SelectNodes("//book[title='" + title + "']"); // $ Alert
        }

        // GOOD: the XPath expression is constant.
        [HttpGet("all/{author}")]
        public void AllBooks(string author)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load("bookstore.xml");
            XmlNodeList nodes = doc.SelectNodes("//book");
        }

        // GOOD: simple-typed parameters cannot carry an injection payload.
        [HttpGet("id/{id}")]
        public void ById(int id)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load("bookstore.xml");
            XmlNode node = doc.SelectSingleNode("//book[@id='" + id + "']");
        }

        // GOOD: not an action method (not public).
        private void Helper(string author)
        {
            XmlDocument doc = new XmlDocument();
            doc.SelectSingleNode("//book[author='" + author + "']");
        }

        // GOOD: not an action method (static).
        public static void StaticHelper(string author)
        {
            XmlDocument doc = new XmlDocument();
            doc.SelectSingleNode("//book[author='" + author + "']");
        }
    }

    public class ReviewsController :
        Controller
    {
        public void Reviews(string reviewer) // $ Source
        {
            XmlDocument doc = new XmlDocument();
            doc.SelectNodes("//review[reviewer='" + reviewer + "']"); // $ Alert
        }
    }

    // GOOD: not a controller, so its parameters are not remote input.
    public class BookRepository
    {
        public void Find(string author)
        {
            XmlDocument doc = new XmlDocument();
            doc.SelectSingleNode("//book[author='" + author + "']");
        }
    }

    // GOOD: the unresolved base type is not an ASP.NET Core controller base type.
    public class BookCache : CacheBase
    {
        public void Find(string author)
        {
            XmlDocument doc = new XmlDocument();
            doc.SelectSingleNode("//book[author='" + author + "']");
        }
    }

    // GOOD: the unresolved type is a generic base type argument, not the base type.
    public class Cache<T> { }

    public class BookRepositoryWithGenericBase : Cache<Controller>
    {
        public void Find(string author)
        {
            XmlDocument doc = new XmlDocument();
            doc.SelectSingleNode("//book[author='" + author + "']");
        }
    }

    // GOOD: the controller base type is on a different partial declaration.
    public partial class PartialBookSearch : ControllerBase { }

    public class SameLineBookSearch : ControllerBase { public void Find(string author) // $ Source
    {
        XmlDocument doc = new XmlDocument();
        doc.SelectSingleNode("//book[author='" + author + "']"); // $ Alert
    } }
}
