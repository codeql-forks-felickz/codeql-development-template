using System;

namespace CustomErrorsTest
{
    public class OnSiteHandler : System.Web.UI.Page
    {
        public void Handle()
        {
            throw new Exception(Environment.UserName);
        }
    }
}
