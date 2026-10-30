using System;
using System.Web.UI;

namespace Shop
{
    public class OrderRepository
    {
        public int CreateOrder(string address) => 1;
    }

    public class Checkout : Page
    {
        protected void btnPlaceOrder_Click(object sender, EventArgs e)
        {
            new OrderRepository().CreateOrder("address");
        }
    }

    public class UnprotectedCheckout : Page
    {
        protected void btnPlaceOrder_Click(object sender, EventArgs e) // $ Alert[cs/web/webforms-request-forgery]
        {
            new OrderRepository().CreateOrder("address");
        }
    }

    public class UnknownMasterCheckout : Page
    {
        protected void btnPlaceOrder_Click(object sender, EventArgs e)
        {
            new OrderRepository().CreateOrder("address");
        }
    }

    public class NoMasterCheckout : Page
    {
        protected void btnPlaceOrder_Click(object sender, EventArgs e) // $ Alert[cs/web/webforms-request-forgery]
        {
            new OrderRepository().CreateOrder("address");
        }
    }
}
