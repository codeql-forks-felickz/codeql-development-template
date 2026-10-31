using System;
using System.Web.UI.WebControls;
using Shop;

namespace WebSite
{
    public partial class PackageTracking : System.Web.UI.Page
    {
        string _carrier = string.Empty;
        string _trackingNumber = string.Empty;
        protected TextBox txtCarrier;
        protected TextBox txtTrackingNumber;

        protected void Page_Load(object sender, EventArgs e)
        {
            if (!IsPostBack)
            {
                _carrier = Request.QueryString["Carrier"]; // $ Source
                _trackingNumber = Request.QueryString["TrackingNumber"]; // $ Source

                if (!string.IsNullOrEmpty(_carrier) && !string.IsNullOrEmpty(_trackingNumber))
                    Response.Redirect(Order.GetPackageTrackingUrl(_carrier, _trackingNumber)); // $ Alert
            }
        }

        protected void btnTrackPackage_Click(object sender, EventArgs e)
        {
            _carrier = txtCarrier.Text; // $ Source
            _trackingNumber = txtTrackingNumber.Text; // $ Source

            Response.Redirect(Order.GetPackageTrackingUrl(_carrier, _trackingNumber)); // $ Alert
        }

        protected void btnTrackPackageSafe_Click(object sender, EventArgs e)
        {
            // Safe: only fixed, trusted URL bases are used.
            Response.Redirect(Order.GetSafePackageTrackingUrl(txtCarrier.Text, txtTrackingNumber.Text));
        }
    }
}
