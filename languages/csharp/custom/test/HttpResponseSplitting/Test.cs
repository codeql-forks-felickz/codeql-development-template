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

    // Juliet CWE-113 `Params_Get_Web_addHeader` style: `Params.Get` into `AddHeader`.
    public class ParamsGetAddHeader
    {
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            string data = req.Params.Get("name"); // $ Source[cs/web/http-response-splitting]
            if (data != null)
            {
                resp.AddHeader("Location", "/author.jsp?lang=" + data); // $ Alert[cs/web/http-response-splitting]
            }
        }

        public void GoodG2B(HttpRequest req, HttpResponse resp)
        {
            string data = "foo";
            resp.AddHeader("Location", "/author.jsp?lang=" + data);
        }

        public void GoodB2G(HttpRequest req, HttpResponse resp)
        {
            string data = req.Params.Get("name");
            if (data != null)
            {
                data = HttpUtility.UrlEncode(data, System.Text.Encoding.UTF8);
                resp.AddHeader("Location", "/author.jsp?lang=" + data);
            }
        }
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
