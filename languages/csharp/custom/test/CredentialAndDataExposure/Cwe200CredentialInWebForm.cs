using System;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace Cwe200
{
    public static class DbConstants
    {
        public const string KEY_UID = "uid";
        public const string KEY_PWD = "pwd";
        public const string KEY_HOST = "host";
    }

    public class ConfigFile
    {
        public string Get(string key) { return null; }
    }

    public class RebuildDatabase : Page
    {
        protected TextBox txtServer;
        protected TextBox txtUserName;
        protected TextBox txtPassword;
        protected TextBox txtMaskedPassword;
        protected Label lblDbPassword;

        public ConfigFile configFile;

        protected void Page_Load(object sender, EventArgs e)
        {
            if (!IsPostBack)
            {
                txtServer.Text = configFile.Get(DbConstants.KEY_HOST);
                txtUserName.Text = configFile.Get(DbConstants.KEY_UID);
                // CWE-200: stored database password rendered into the page.
                txtPassword.Text = configFile.Get(DbConstants.KEY_PWD); // $ Alert
                lblDbPassword.Text = "Password: " + configFile.Get("password"); // $ Alert
            }
        }

        protected void Page_Init(object sender, EventArgs e)
        {
            // Safe: a password-mode TextBox never renders its Text value.
            txtMaskedPassword.TextMode = TextBoxMode.Password;
            txtMaskedPassword.Text = configFile.Get(DbConstants.KEY_PWD);
        }
    }
}
