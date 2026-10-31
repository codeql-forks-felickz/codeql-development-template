using System;
using System.Text;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace WebFormsApp
{
    public interface IDbProvider
    {
        string AddComment(string productCode, string comment);
    }

    public class DbProvider : IDbProvider
    {
        public string AddComment(string productCode, string comment)
        {
            string output = null;
            try
            {
                Save(productCode, comment);
            }
            catch (Exception ex)
            {
                // Exception message is returned to the caller and later displayed on a page.
                output = ex.Message; // $ Source
            }
            return output;
        }

        private void Save(string productCode, string comment) { }
    }

    public class StoredComments : Page
    {
        protected Label lblOutput;
        private IDbProvider du = new DbProvider();

        protected void btnSave_Click(object sender, EventArgs e)
        {
            lblOutput.Text = du.AddComment("code", "comment"); // $ Alert
        }

        protected void btnSaveSafe_Click(object sender, EventArgs e)
        {
            try
            {
                du.AddComment("code", "comment");
            }
            catch (Exception ex)
            {
                Log(ex.ToString());
                // GOOD: a generic message is shown to the user.
                lblOutput.Text = "An error occurred.";
            }
        }

        protected void btnShowStack_Click(object sender, EventArgs e)
        {
            try
            {
                du.AddComment("code", "comment");
            }
            catch (Exception ex)
            {
                // Already reported by the upstream query.
                lblOutput.Text = ex.StackTrace; // $ Alert
            }
        }

        private void Log(string message) { }
    }

    public class ExploitDebug : Page
    {
        protected void btnGo_Click(object sender, EventArgs e)
        {
            StringBuilder strBuilder = new StringBuilder();
            strBuilder.AppendFormat("Current Dir: {0}", Environment.CurrentDirectory); // $ Source
            strBuilder.AppendLine();
            strBuilder.AppendFormat("UserName: {0}", Environment.UserName); // $ Source
            strBuilder.AppendLine();
            strBuilder.AppendFormat("Machine Name: {0}", Environment.MachineName); // $ Source
            strBuilder.AppendLine();
            strBuilder.AppendFormat("OS Version: {0}", Environment.OSVersion); // $ Source
            strBuilder.AppendLine();

            // `customErrors` is off in Web.config, so the unhandled exception is rendered to the client.
            throw new Exception(strBuilder.ToString()); // $ Alert
        }

        protected void btnSafe_Click(object sender, EventArgs e)
        {
            // GOOD: the exception message does not contain system information.
            throw new InvalidOperationException("Operation failed.");
        }

        protected void btnWrap_Click(object sender, EventArgs e)
        {
            try
            {
                btnSafe_Click(sender, e);
            }
            catch (Exception ex)
            {
                // Not reported: re-throwing a wrapped exception is only reported for system information.
                throw new Exception("Wrapped", ex);
            }
        }
    }

    public class NotAWebPage
    {
        public void Run()
        {
            // GOOD: not rendered by ASP.NET.
            throw new Exception("User: " + Environment.UserName);
        }
    }
}
