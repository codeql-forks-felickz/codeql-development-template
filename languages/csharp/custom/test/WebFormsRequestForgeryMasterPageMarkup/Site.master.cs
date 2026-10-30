using System;
using System.Web.UI;

namespace Shop
{
    public class SiteMaster : MasterPage
    {
        protected void Page_Init(object sender, EventArgs e)
        {
            Page.ViewStateUserKey = "user";
        }
    }
}
