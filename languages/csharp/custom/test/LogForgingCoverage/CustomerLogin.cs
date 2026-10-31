// Reduced from an ASP.NET WebForms login page that logs the submitted e-mail
// address through a log4net `ILog` logger.
using System;
using System.Globalization;
using System.Reflection;
using System.Web.UI;
using System.Web.UI.WebControls;
using log4net;

namespace WebGoat.WebGoatCoins
{
    public partial class CustomerLogin : Page
    {
        protected TextBox txtUserName;
        protected TextBox txtPassword;
        protected Label labelError;

        ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        protected void ButtonLogOn_Click(object sender, EventArgs e)
        {
            string email = txtUserName.Text; // $ Source
            string pwd = txtPassword.Text; // $ Source

            log.Info("User " + email + " attempted to log in with password " + pwd); // $ Alert

            log.Debug("User " + email); // $ Alert
            log.Warn("User " + email); // $ Alert
            log.Fatal("User " + email); // $ Alert
            log.Error("Login failed for " + email, new Exception()); // $ Alert

            log.InfoFormat("User {0} attempted to log in", email); // $ Alert
            log.ErrorFormat("User {0} {1}", email, "failed"); // $ Alert
            log.WarnFormat("User {0} {1} {2}", "a", "b", email); // $ Alert
            log.DebugFormat("User " + email + " {0} {1} {2} {3}", "a", "b", "c", "d"); // $ Alert
            log.FatalFormat(CultureInfo.InvariantCulture, "User " + email + " {0}", "a"); // $ Alert

            // Not modeled: elements of the implicit `params object[]` array.
            log.DebugFormat("User {0} {1} {2} {3}", "a", "b", "c", email); // $ MISSING: Alert
            log.FatalFormat(CultureInfo.InvariantCulture, "User {0}", email); // $ MISSING: Alert

            // Safe: CR/LF removed before logging.
            log.Info("User " + email.Replace("\r", "").Replace("\n", "") + " attempted to log in");

            // Safe: constant message.
            log.Info("Login attempt");
            log.InfoFormat("Login attempt {0}", "constant");
        }
    }
}
