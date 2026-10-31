using System.Net;
using System.Text;
using System.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Juliet
{
    // Juliet CWE-81 `XSS_Error_Message` style: query string reflected into `StatusDescription`.
    public class ErrorMessage
    {
        public void Bad(System.Web.HttpRequest req, System.Web.HttpResponse resp)
        {
            string data = "";
            if (req.QueryString["id"] != null)
            {
                data = req.QueryString["id"]; // $ Source[cs/web/xss]
            }
            if (data != null)
            {
                resp.StatusCode = 404;
                resp.StatusDescription = "<br>Bad() - Parameter name has value " + data; // $ Alert[cs/web/xss]
            }
        }

        public void GoodG2B(System.Web.HttpRequest req, System.Web.HttpResponse resp)
        {
            string data = "foo";
            resp.StatusCode = 404;
            resp.StatusDescription = "<br>Bad() - Parameter name has value " + data;
        }

        public void GoodB2G(System.Web.HttpRequest req, HttpResponseBase resp)
        {
            string data = req.QueryString["id"];
            resp.StatusDescription = "<br>Parameter name has value " + HttpUtility.HtmlEncode(data);
        }
    }
}

namespace WebFox.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class XSS : ControllerBase
    {
        public async void xss(string userInfo) // $ Source[cs/web/xss]
        {
            var context = this.ControllerContext.HttpContext;
            await context.Response.WriteAsync("<body>" + userInfo + "</body>"); // $ Alert[cs/web/xss]
        }

        public async void xssEncoding(string userInfo) // $ Source[cs/web/xss]
        {
            await ControllerContext.HttpContext.Response.WriteAsync("<p>" + userInfo + "</p>", Encoding.UTF8); // $ Alert[cs/web/xss]
        }

        public async void safe(string userInfo)
        {
            await ControllerContext.HttpContext.Response.WriteAsync("<body>" + WebUtility.HtmlEncode(userInfo) + "</body>");
        }
    }

    namespace CookieXss
    {
        public class CookieOutput
        {
            public void Render(HttpRequest request, System.Web.UI.WebControls.Label label)
            {
                var cookies = request.Cookies; // $ Source[cs/web/xss]
                string value = cookies["displayName"].Value;
                label.Text = value; // $ Alert[cs/web/xss]
                label.Text = HttpUtility.HtmlEncode(value);
            }
        }
    }
}
