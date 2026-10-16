using System;
using System.Data;
using System.Data.SqlClient;

namespace Shop
{
    public interface IDbProvider
    {
        DataSet GetOrders(int customerNumber);
        DataSet GetOrderDetails(int orderNumber);
    }

    public class SqlDbProvider : IDbProvider
    {
        public DataSet GetOrders(int customerNumber)
        {
            SqlCommand command = new SqlCommand("SELECT * FROM Orders WHERE customerNumber = @num", new SqlConnection());
            command.Parameters.Add(new SqlParameter("@num", customerNumber)); // $ Alert
            command.ExecuteNonQuery();
            return new DataSet();
        }

        public DataSet GetOrderDetails(int orderNumber)
        {
            SqlCommand command = new SqlCommand("SELECT * FROM OrderDetails WHERE orderNumber = @num", new SqlConnection());
            SqlParameter p = new SqlParameter("@num", SqlDbType.Int, 0);
            p.Value = orderNumber; // $ Alert
            command.Parameters.Add(p);
            command.ExecuteNonQuery();
            return new DataSet();
        }
    }

    // Orders page that selects the customer from an unsigned cookie and loads
    // any order number supplied in the request.
    public class Orders : System.Web.UI.Page
    {
        private IDbProvider du = new SqlDbProvider();

        protected void Page_Load(object sender, EventArgs e)
        {
            int id;
            if (Request.Cookies["customerNumber"] == null || !int.TryParse(Request.Cookies["customerNumber"].Value.ToString(), out id)) // $ Source
            {
                return;
            }
            du.GetOrders(id);

            string orderNumber = Request["orderNumber"]; // $ Source
            if (orderNumber != null)
            {
                du.GetOrderDetails(int.Parse(orderNumber));
            }
        }
    }

    // Safe counterpart: the customer comes from the authenticated principal and
    // the requested order is checked against that customer.
    public class SafeOrders : System.Web.UI.Page
    {
        private IDbProvider du = new SqlDbProvider();

        protected void Page_Load(object sender, EventArgs e)
        {
            int customer = LookupCustomer(User.Identity.Name);
            du.GetOrders(customer);

            string orderNumber = Request["orderNumber"];
            if (orderNumber != null && OrderBelongsTo(int.Parse(orderNumber), customer))
            {
                du.GetOrderDetails(int.Parse(orderNumber));
            }
        }

        private int LookupCustomer(string name) => 0;

        private bool OrderBelongsTo(int order, int customer) => false;
    }
}
