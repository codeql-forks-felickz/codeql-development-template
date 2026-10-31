using System;
using System.Text.RegularExpressions;

namespace App
{
    // Reduced from WebGoat.NET Content/RegexDoS.aspx.cs. User-controlled regular
    // expressions are already reported by `cs/regex-injection`, so this query must
    // not report them again.
    public partial class RegexDoS : System.Web.UI.Page
    {
        protected System.Web.UI.WebControls.Label lblError;
        protected System.Web.UI.WebControls.TextBox txtUsername;
        protected System.Web.UI.WebControls.TextBox txtPassword;

        protected void btnCreate_Click(object sender, EventArgs e)
        {
            string userName = txtUsername.Text;
            string password = txtPassword.Text;
            Regex testPassword = new Regex(userName);
            Match match = testPassword.Match(password);
            lblError.Text = match.Success ? "Do not include name in password." : "Good password.";
        }
    }
}
