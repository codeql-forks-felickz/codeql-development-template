using System.Web.Mvc;
using System.Web.Services;

namespace Bank.WebServices
{
    [Authorize]
    public class ConfiguredService : WebService
    {
        [WebMethod]
        public void TransferFunds()
        {
            System.Console.WriteLine("transfer");
        }
    }
}
