// A master page binds the view state of every content page to the user, so postbacks are protected.
using System;
using System.Web.UI;

namespace Shop
{
    public class SiteMaster : MasterPage
    {
        protected void Page_Init(object sender, EventArgs e)
        {
            Page.ViewStateUserKey = Page.Session.SessionID;
        }
    }

    public class OrderRepository
    {
        public int CreateOrder(string address) => 1;
    }

    // GOOD: protected by the master page.
    public class Checkout : Page
    {
        protected void btnPlaceOrder_Click(object sender, EventArgs e)
        {
            new OrderRepository().CreateOrder("address");
        }
    }
}
