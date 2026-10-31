// Sanitized reproduction of a WCF web service that updates an order over HTTP GET.
using System;
using System.ServiceModel;
using System.ServiceModel.Web;

namespace Shop.Checkout
{
    public class OrderRepository
    {
        public void UpdateShipAddress(int orderId, string address) { }
        public int GetLastOrderId() => 0;
    }

    [ServiceContract(Namespace = "")]
    public class Orders
    {
        private readonly OrderRepository _repository = new OrderRepository();

        // BAD: a cross-site GET (e.g. an <img> tag) redirects the victim's shipment.
        [OperationContract]
        [WebInvoke(Method = "GET")]
        public void UpdateShipAddress(int OrderId, string Address) // $ Alert[cs/web/wcf-state-change-over-get]
        {
            _repository.UpdateShipAddress(OrderId, Address);
        }

        // BAD: an ownership check does not stop a forged request sent with the victim's cookies.
        [OperationContract]
        [WebGet]
        public void CancelOrder(int orderId) // $ Alert[cs/web/wcf-state-change-over-get]
        {
            if (ServiceSecurityContext.Current.PrimaryIdentity.Name == "owner")
                _repository.UpdateShipAddress(orderId, null);
        }

        // GOOD: read-only GET.
        [OperationContract]
        [WebGet]
        public int GetLastOrderId() => _repository.GetLastOrderId();

        // GOOD: requires POST.
        [OperationContract]
        [WebInvoke(Method = "POST")]
        public void SaveShipAddress(int orderId, string address) => _repository.UpdateShipAddress(orderId, address);

        // GOOD: WebInvoke defaults to POST.
        [OperationContract]
        [WebInvoke]
        public void DeleteOrder(int orderId) { }
    }

    [ServiceContract]
    public interface IOrderService
    {
        [OperationContract]
        [WebGet]
        void PlaceOrder(int cartId);

        [OperationContract]
        [WebInvoke(Method = "POST")]
        void RemoveOrder(int orderId);
    }

    public class OrderService : IOrderService
    {
        // BAD: the contract exposes this operation over GET.
        public void PlaceOrder(int cartId) { } // $ Alert[cs/web/wcf-state-change-over-get]

        // GOOD: POST only.
        public void RemoveOrder(int orderId) { }
    }
}
