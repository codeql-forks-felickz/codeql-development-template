using System;
using System.Web;
using System.Web.UI;

namespace Test
{
    // WebGoat-style anonymous page copying a query parameter into Response.Headers,
    // in an application whose Web.config disables header checking.
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

        protected void Safe()
        {
            string header = Request.QueryString["Header"];
            Response.Headers.Add("X-Header", HttpUtility.UrlEncode(header));
        }
    }
}
