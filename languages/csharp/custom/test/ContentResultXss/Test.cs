using System.Net;
using Microsoft.AspNetCore.Mvc;

namespace Xss.Server.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SearchController : ControllerBase
    {
        // Default content type is `text/plain; charset=utf-8`, which browsers do not
        // render as HTML, so this is not reported.
        [HttpGet(Name = "Search")]
        public IActionResult Search(string query)
        {
            string result = "You searched for: " + query;
            return new ContentResult() { Content = result };
        }

        [HttpGet(Name = "SearchHtml")]
        public IActionResult SearchHtml(string query) // $ Source[cs/web/content-result-xss]
        {
            string result = "<p>You searched for: " + query + "</p>";
            return new ContentResult() { Content = result, ContentType = "text/html" }; // $ Alert[cs/web/content-result-xss]
        }

        [HttpGet(Name = "SearchHtmlProperty")]
        public IActionResult SearchHtmlProperty(string query) // $ Source[cs/web/content-result-xss]
        {
            var r = new ContentResult();
            r.ContentType = "text/html; charset=utf-8";
            r.Content = "<p>" + query + "</p>"; // $ Alert[cs/web/content-result-xss]
            return r;
        }

        [HttpGet(Name = "SearchHelper")]
        public IActionResult SearchHelper(string query) // $ Source[cs/web/content-result-xss]
        {
            return Content("<p>" + query + "</p>", "text/html"); // $ Alert[cs/web/content-result-xss]
        }

        // Safe: HTML encoded.
        [HttpGet(Name = "SearchEncoded")]
        public IActionResult SearchEncoded(string query)
        {
            return new ContentResult() { Content = "<p>" + WebUtility.HtmlEncode(query) + "</p>", ContentType = "text/html" };
        }

        // Safe: non-HTML content types.
        [HttpGet(Name = "SearchJson")]
        public IActionResult SearchJson(string query)
        {
            Content(query);
            Content(query, "text/plain");
            return new ContentResult() { Content = query, ContentType = "application/json" };
        }
    }
}
