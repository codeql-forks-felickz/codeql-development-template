// Sanitized reproduction of a Web Forms checkout page whose postback handler places an order
// without binding the view state to the user or validating an anti-forgery token.
using System;
using System.Web.Helpers;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace Shop.Checkout
{
    public class Order
    {
        public string ShipAddress { get; set; }
        public string ShipVia { get; set; }
        public decimal Total { get; set; }
    }

    public class OrderRepository
    {
        public int CreateOrder(Order order) => 1;
        public Order GetOrder(int id) => null;
    }

    public class CreditCard
    {
        public void ChargeCard(decimal amount) { }
    }

    public class Checkout : Page
    {
        protected TextBox txtShipAddress;
        protected DropDownList ddlShipVia;
        protected TextBox txtCreditCardNumber;
        private readonly OrderRepository _orderRepository = new OrderRepository();
        private readonly CreditCard _creditCard = new CreditCard();

        protected void Page_Load(object sender, EventArgs e)
        {
            // Lifecycle handler: not a postback event handler.
        }

        // BAD: a forged cross-site postback places an order and charges the victim's card.
        protected void btnPlaceOrder_Click(object sender, EventArgs e) // $ Alert[cs/web/webforms-request-forgery]
        {
            var order = new Order { ShipAddress = txtShipAddress.Text, ShipVia = ddlShipVia.SelectedValue, Total = 10m };
            _creditCard.ChargeCard(order.Total);
            _orderRepository.CreateOrder(order);
            SaveCardForUser();
        }

        // BAD: the state change happens in a helper method of the page.
        protected void btnSaveCard_Click(object sender, EventArgs e) // $ Alert[cs/web/webforms-request-forgery]
        {
            StoreCard();
        }

        private void StoreCard() => SaveCardForUser();

        private void SaveCardForUser() { }

        // GOOD: read-only handler.
        protected void btnView_Click(object sender, EventArgs e)
        {
            var order = _orderRepository.GetOrder(1);
            Response.Redirect("Receipt.aspx");
        }
    }

    public class SecureBasePage : Page
    {
        protected override void OnInit(EventArgs e)
        {
            base.OnInit(e);
            ViewStateUserKey = Session.SessionID;
        }
    }

    // GOOD: the base page binds the view state to the user.
    public class SecureCheckout : SecureBasePage
    {
        protected TextBox txtShipAddress;
        private readonly OrderRepository _orderRepository = new OrderRepository();

        protected void btnPlaceOrder_Click(object sender, EventArgs e)
        {
            _orderRepository.CreateOrder(new Order { ShipAddress = txtShipAddress.Text });
        }
    }

    // GOOD: the page validates an anti-forgery token.
    public class ValidatedCheckout : Page
    {
        private readonly OrderRepository _orderRepository = new OrderRepository();

        protected void btnPlaceOrder_Click(object sender, EventArgs e)
        {
            ValidateRequest();
            _orderRepository.CreateOrder(new Order());
        }

        private void ValidateRequest() => AntiForgery.Validate();

        protected void btnUpdateOrder_Click(object sender, EventArgs e) // $ Alert[cs/web/webforms-request-forgery]
        {
            _orderRepository.CreateOrder(new Order());
        }
    }

    public class LifecycleValidatedCheckout : Page
    {
        private readonly OrderRepository _orderRepository = new OrderRepository();

        protected void Page_Init(object sender, EventArgs e)
        {
            AntiForgery.Validate();
        }

        protected void btnPlaceOrder_Click(object sender, EventArgs e)
        {
            _orderRepository.CreateOrder(new Order());
        }
    }

    public class TaintedMixedCheckout : Page
    {
        protected void btnValidated_Click(object sender, EventArgs e)
        {
            AntiForgery.Validate();
            UpdateOrder(Request.Params["validated"]);
        }

        protected void btnUnvalidated_Click(object sender, EventArgs e) // $ Alert[cs/web/webforms-request-forgery]
        {
            UpdateOrder(Request.Params["unvalidated"]); // $ Alert[cs/web/webforms-request-forgery]
        }

        private void UpdateOrder(string value) { }
    }

    public class CmsPage : Page
    {
        protected void btnChangePassword_Click(object sender, EventArgs e) // $ Alert[cs/web/webforms-request-forgery]
        {
            ChangePassword();
        }

        protected void btnCreateComment_Click(object sender, EventArgs e) // $ Alert[cs/web/webforms-request-forgery]
        {
            CreateComment();
        }

        protected void btnUploadFile_Click(object sender, EventArgs e) // $ Alert[cs/web/webforms-request-forgery]
        {
            UploadFile();
        }

        protected void btnRebuildDatabase_Click(object sender, EventArgs e) // $ Alert[cs/web/webforms-request-forgery]
        {
            RebuildDatabase();
        }

        protected void btnValidatedUpload_Click(object sender, EventArgs e)
        {
            AntiForgery.Validate();
            UploadFile();
        }

        private void ChangePassword() { }
        private void CreateComment() { }
        private void UploadFile() { }
        private void RebuildDatabase() { }
    }
}
