using Microsoft.AspNetCore.Mvc;
using Shop;

namespace WebGoatCore.Controllers
{
    public class CheckoutController : Controller
    {
        public IActionResult GoToExternalTracker(string carrier, string trackingNumber) // $ Source
        {
            return Redirect(Order.GetPackageTrackingUrl(carrier, trackingNumber)); // $ Alert
        }

        public IActionResult GoToSafeExternalTracker(string carrier, string trackingNumber)
        {
            // Safe: only fixed, trusted URL bases are used.
            return Redirect(Order.GetSafePackageTrackingUrl(carrier, trackingNumber));
        }
    }
}
