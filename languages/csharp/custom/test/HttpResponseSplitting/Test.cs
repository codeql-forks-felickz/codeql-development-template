using System;
using System.Web;
using System.Web.UI;

namespace Test
{
    // Juliet-style: request data concatenated into the Location header.
    public class LocationHeaderHandler : IHttpHandler
    {
        public void ProcessRequest(HttpContext ctx)
        {
            string data = ctx.Request.QueryString["lang"]; // $ Source[cs/web/http-response-splitting]
            ctx.Response.AddHeader("Location", "/author.aspx?lang=" + data); // $ Alert[cs/web/http-response-splitting]
        }
    }

    // WebGoat-style: query parameter copied directly into Response.Headers.
    public class HeaderInjection : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string header = Request.QueryString["Header"]; // $ Source[cs/web/http-response-splitting]
            if (header != null)
            {
                Response.Headers.Add("X-Header", header); // $ Alert[cs/web/http-response-splitting]
            }
        }

        protected void OtherSinks()
        {
            string v = Request["v"]; // $ Source[cs/web/http-response-splitting]
            Response.AppendHeader("X-Value", v); // $ Alert[cs/web/http-response-splitting]
            Response.Headers.Set("X-Value", v); // $ Alert[cs/web/http-response-splitting]
            Response.Headers["X-Value"] = v; // $ Alert[cs/web/http-response-splitting]
            Response.RedirectLocation = "/next?v=" + v; // $ Alert[cs/web/http-response-splitting]
        }

        protected void SafeUsages()
        {
            string v = Request.QueryString["v"]; // $ Source[cs/web/http-response-splitting]
            // Constant header values are safe.
            Response.AddHeader("X-Constant", "value");
            // URL encoding removes CR and LF characters.
            Response.AddHeader("Location", "/a?v=" + HttpUtility.UrlEncode(v));
            Response.AddHeader("Location", "/a?v=" + Server.UrlEncode(v));
            // Stripping CR/LF characters is a sanitizer.
            Response.AddHeader("X-Value", v.Replace("\r", "").Replace("\n", ""));
            Response.AddHeader("X-Value", StripNewLines(v));
            // Numeric data cannot contain CR/LF.
            Response.AddHeader("X-Id", int.Parse(v).ToString());
            // HTML encoding does NOT remove CR/LF, so it is not a sanitizer.
            Response.AddHeader("X-Value", HttpUtility.HtmlEncode(v)); // $ Alert[cs/web/http-response-splitting]
        }

        private static string StripNewLines(string s) => s.Replace("\n", string.Empty).Replace("\r", string.Empty);
    }

    public class MvcStyle
    {
        public void Handle(HttpRequest request, HttpResponseBase response)
        {
            string v = request.QueryString["v"]; // $ Source[cs/web/http-response-splitting]
            response.AddHeader("X-Value", v); // $ Alert[cs/web/http-response-splitting]
            response.Headers.Add("X-Value", v); // $ Alert[cs/web/http-response-splitting]
        }
    }
}
