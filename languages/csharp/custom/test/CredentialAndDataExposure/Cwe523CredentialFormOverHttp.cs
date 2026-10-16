using System.Web;

namespace Cwe523
{
    public class LoginPage
    {
        // CWE-523: a login form posting credentials to an http:// endpoint.
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            resp.Write("<form action='http://hostname.com/j_security_check' method='post'>"); // $ Alert
            resp.Write("<table>");
            resp.Write("<tr><td>Name:</td>");
            resp.Write("<td><input type='text' name='j_username'></td></tr>");
            resp.Write("<tr><td>Password:</td>");
            resp.Write("<td><input type='password' name='j_password' size='8'></td>");
            resp.Write("</tr>");
            resp.Write("</table><br />");
            resp.Write("<input type='submit' value='login'>");
            resp.Write("</form>");
        }

        // CWE-523: the whole form is a single string.
        public void BadSingleString(HttpResponse resp)
        {
            resp.Write("<form method=\"post\" action=\"HTTP://example.com/login\"><input type=\"password\" name=\"pw\"></form>"); // $ Alert
        }

        // Safe: credentials are posted over TLS.
        public void GoodHttps(HttpRequest req, HttpResponse resp)
        {
            resp.Write("<form action='https://hostname.com/j_security_check' method='post'>");
            resp.Write("<td><input type='text' name='j_username'></td></tr>");
            resp.Write("<td><input type='password' name='j_password' size='8'></td>");
            resp.Write("</form>");
        }

        // Safe: an http:// form that does not collect a password.
        public void GoodNoPassword(HttpResponse resp)
        {
            resp.Write("<form action='http://hostname.com/search' method='get'>");
            resp.Write("<input type='text' name='q'>");
            resp.Write("</form>");
        }
    }
}
