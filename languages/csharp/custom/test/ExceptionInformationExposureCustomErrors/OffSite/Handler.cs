using System;

namespace CustomErrorsTest
{
    public class OffSiteHandler : System.Web.UI.Page
    {
        public void Handle()
        {
            throw new Exception(Environment.UserName); // $ Alert
        }
    }
}
