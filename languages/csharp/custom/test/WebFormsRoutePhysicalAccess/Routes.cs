namespace System.Web.Routing
{
    public class RouteCollection
    {
        public void MapPageRoute(string routeName, string routeUrl, string physicalFile, bool checkPhysicalUrlAccess) { }
    }
}

namespace Routing
{
    public class RouteConfig
    {
        public void RegisterRoutes(System.Web.Routing.RouteCollection routes)
        {
            routes.MapPageRoute("orders", "orders", "~/Orders.aspx", checkPhysicalUrlAccess: false); // $ Alert[cs/web/webforms-route-physical-url-access-disabled]
            routes.MapPageRoute("public", "public", "~/Public.aspx", checkPhysicalUrlAccess: true);
        }
    }
}
