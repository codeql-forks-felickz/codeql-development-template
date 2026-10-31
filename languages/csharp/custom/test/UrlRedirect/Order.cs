namespace Shop
{
    public class Order
    {
        // Builds an absolute URL whose host comes from the caller supplied carrier.
        public static string GetPackageTrackingUrl(string Carrier, string TrackingNumber)
        {
            string trackingUrl;
            Carrier = Carrier.ToLower();
            switch (Carrier)
            {
                case "fedex":
                    trackingUrl = string.Format("http://www.fedex.com/Tracking?tracknumbers={0}&action=track", TrackingNumber);
                    break;
                case "ups":
                    trackingUrl = string.Format("http://wwwapps.ups.com/WebTracking/track?loc=en_US&trackNums={0}", TrackingNumber);
                    break;
                default:
                    trackingUrl = string.Format("http://{0}?TrackingNumber={1}", Carrier, TrackingNumber);
                    break;
            }
            return trackingUrl;
        }

        // Safe: the carrier only selects from fixed, trusted URL bases.
        public static string GetSafePackageTrackingUrl(string Carrier, string TrackingNumber)
        {
            switch (Carrier.ToLower())
            {
                case "ups":
                    return string.Format("http://wwwapps.ups.com/WebTracking/track?loc=en_US&trackNums={0}", TrackingNumber);
                default:
                    return string.Format("http://www.fedex.com/Tracking?tracknumbers={0}&action=track", TrackingNumber);
            }
        }
    }
}
