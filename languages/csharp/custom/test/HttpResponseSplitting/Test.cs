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

        protected void AliasedHeaders(HttpRequest request, HttpResponseBase response)
        {
            string v = request.QueryString["v"]; // $ Source[cs/web/http-response-splitting]
            var headers = response.Headers;
            headers.Add("X-Add", v); // $ Alert[cs/web/http-response-splitting]
            headers.Set("X-Set", v); // $ Alert[cs/web/http-response-splitting]
            headers["X-Indexer"] = v; // $ Alert[cs/web/http-response-splitting]

            var unrelated = new System.Collections.Specialized.NameValueCollection();
            unrelated.Add("X-Add", v);
            unrelated.Set("X-Set", v);
            unrelated["X-Indexer"] = v;
        }

        protected void IncompleteNewLineReplacement(HttpRequest request, HttpResponse response)
        {
            string v = request.QueryString["v"]; // $ Source[cs/web/http-response-splitting]
            response.AddHeader("X-LfOnly", v.Replace("\n", "")); // $ Alert[cs/web/http-response-splitting]
            response.AddHeader("X-CrLfPair", v.Replace("\r\n", "")); // $ Alert[cs/web/http-response-splitting]
            response.AddHeader("X-ReintroducedLf", v.Replace("\r", "\n")); // $ Alert[cs/web/http-response-splitting]
            response.AddHeader("X-ReintroducedCr", v.Replace("\n", "\r\n")); // $ Alert[cs/web/http-response-splitting]
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

    // Juliet CWE-113 `QueryString_Web_addHeader` style: guarded `QueryString` read into `AddHeader`.
    public class QueryStringAddHeader
    {
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            string data = "";
            if (req.QueryString["id"] != null)
            {
                data = req.QueryString["id"]; // $ Source[cs/web/http-response-splitting]
            }
            if (data != null)
            {
                resp.AddHeader("Location", "/author.jsp?lang=" + data); // $ Alert[cs/web/http-response-splitting]
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

    public class ResponseRedirectAndCookie
    {
        protected void Write(HttpRequest request, HttpResponseBase response)
        {
            string v = request.QueryString["v"]; // $ Source[cs/web/http-response-splitting]
            response.Redirect("/next?v=" + v); // $ Alert[cs/web/http-response-splitting]
            response.Cookies["lang"].Value = v; // $ Alert[cs/web/http-response-splitting]
            var cookie = new System.Web.HttpCookie("lang", v); // $ Alert[cs/web/http-response-splitting]
            response.Cookies.Add(cookie);

            response.Redirect("/next?v=" + HttpUtility.UrlEncode(v));
            response.Cookies["safe"].Value = "constant";
            response.Cookies.Add(new System.Web.HttpCookie("safe", "constant"));
        }
    }
}
