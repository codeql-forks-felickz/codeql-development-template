using System;
using System.Web.UI.WebControls;

namespace WebSite.Account
{
    public partial class Register : System.Web.UI.Page
    {
        protected CreateUserWizard RegisterUser;

        protected void Page_Load(object sender, EventArgs e)
        {
            RegisterUser.ContinueDestinationPageUrl = Request.QueryString["ReturnUrl"]; // $ Alert
        }

        protected void RegisterUser_CreatedUser(object sender, EventArgs e)
        {
            string continueUrl = RegisterUser.ContinueDestinationPageUrl;
            if (String.IsNullOrEmpty(continueUrl))
            {
                continueUrl = "~/";
            }
            Response.Redirect(continueUrl);
        }
    }

    public partial class SafeRegister : System.Web.UI.Page
    {
        protected CreateUserWizard RegisterUser;

        protected void Page_Load(object sender, EventArgs e)
        {
            // Safe: a fixed, local destination.
            RegisterUser.ContinueDestinationPageUrl = "~/Default.aspx";
        }

        protected void RegisterUser_CreatedUser(object sender, EventArgs e)
        {
            Response.Redirect(RegisterUser.ContinueDestinationPageUrl);
        }
    }
}
