using System;
using System.Security.Permissions;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Threading;

namespace WebSite.Checkout
{
    public class Order
    {
        public int OrderId;
        public string CustomerName;
        public string ShipAddress;
        public string ShipCity;
    }

    public class OrderRepository
    {
        public Order GetOrderById(int id) => null;
        public void UpdateOrder(Order order) { }
        public void DeleteOrder(Order order) { }
    }

    [ServiceContract(Namespace = "")]
    public class Orders
    {
        private readonly OrderRepository repo = new OrderRepository();

        // BAD: anyone can redirect the shipment of any order.
        [OperationContract]
        [WebInvoke(Method = "GET")]
        public void UpdateShipAddress(int OrderId, string Address, string City) // $ Alert[cs/web/missing-service-operation-access-control]
        {
            var order = repo.GetOrderById(OrderId);
            order.ShipAddress = Address;
            order.ShipCity = City;
            repo.UpdateOrder(order);
        }

        // GOOD: checks that the caller owns the order.
        [OperationContract]
        public void ChangeShipCity(int orderId, string city)
        {
            var order = repo.GetOrderById(orderId);
            if (order.CustomerName != ServiceSecurityContext.Current.PrimaryIdentity.Name)
                throw new UnauthorizedAccessException();
            order.ShipCity = city;
            repo.UpdateOrder(order);
        }

        // GOOD: role check in code.
        [OperationContract]
        public void DeleteOrder(int orderId)
        {
            if (!Thread.CurrentPrincipal.IsInRole("Admin"))
                throw new UnauthorizedAccessException();
            repo.DeleteOrder(repo.GetOrderById(orderId));
        }

        // GOOD: declarative role demand.
        [OperationContract]
        [PrincipalPermission(SecurityAction.Demand, Role = "Admin")]
        public void CancelOrder(int orderId)
        {
            repo.DeleteOrder(repo.GetOrderById(orderId));
        }

        // GOOD: read-only operation.
        [OperationContract]
        [WebGet]
        public Order GetOrder(int orderId)
        {
            return repo.GetOrderById(orderId);
        }

        // GOOD: not a service operation.
        public void UpdateInternal(int orderId)
        {
            repo.UpdateOrder(repo.GetOrderById(orderId));
        }
    }

    [ServiceContract]
    public interface IOrderService
    {
        [OperationContract]
        void RemoveOrder(int orderId);

        [OperationContract]
        [PrincipalPermission(SecurityAction.Demand, Role = "Admin")]
        void PurgeOrder(int orderId);
    }

    public class OrderService : IOrderService
    {
        private readonly OrderRepository repo = new OrderRepository();

        // BAD: implements an operation of a service contract interface without authorization.
        public void RemoveOrder(int orderId) // $ Alert[cs/web/missing-service-operation-access-control]
        {
            repo.DeleteOrder(repo.GetOrderById(orderId));
        }

        // GOOD: the contract demands a role.
        public void PurgeOrder(int orderId)
        {
            repo.DeleteOrder(repo.GetOrderById(orderId));
        }
    }
}
