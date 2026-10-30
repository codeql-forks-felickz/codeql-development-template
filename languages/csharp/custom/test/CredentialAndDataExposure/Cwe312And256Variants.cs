using System;
using System.Text;
using Identity = Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using MySql.Data.MySqlClient;

namespace Cwe312.Ef6
{
    public class OrderPayment
    {
        public int OrderId { get; set; }
        public string CreditCardNumber { get; set; }
    }

    public class NorthwindContext : System.Data.Entity.DbContext
    {
        public System.Data.Entity.DbSet<OrderPayment> OrderPayments { get; set; }
    }

    public class OrderRepository
    {
        private readonly NorthwindContext _context = new NorthwindContext();

        // CWE-312: Entity Framework 6 entity with the full card number.
        public void CreateOrderPayment(int OrderId, string CreditCardNumber)
        {
            var orderPayment = new OrderPayment()
            {
                CreditCardNumber = CreditCardNumber, // $ Alert
                OrderId = OrderId
            };
            _context.OrderPayments.Add(orderPayment);
            _context.SaveChanges();
        }
    }
}

namespace Cwe312.IdentityStore
{
    public class OrderPayment
    {
        public int OrderId { get; set; }
        public string CreditCardNumber { get; set; }
        public string? CVV { get; set; }
    }

    // The context derives from DbContext through the generic IdentityDbContext<TUser>.
    public class NorthwindContext : IdentityDbContext<Identity.IdentityUser>
    {
        public Microsoft.EntityFrameworkCore.DbSet<OrderPayment> OrderPayments { get; set; }
    }

    public class OrderRepository
    {
        private readonly NorthwindContext _context = new NorthwindContext();

        // CWE-312: full card number persisted through an Identity-based EF Core context.
        public void CreateOrderPayment(int orderId, string creditCardNumber)
        {
            var orderPayment = new OrderPayment()
            {
                CreditCardNumber = creditCardNumber, // $ Alert
                OrderId = orderId
            };
            _context.OrderPayments.Add(orderPayment);
            _context.SaveChanges();
        }

        // Safe: only the last four digits are kept.
        public void CreateOrderPaymentLastFour(int orderId, string creditCardNumber)
        {
            var orderPayment = new OrderPayment()
            {
                CreditCardNumber = "************" + creditCardNumber.Substring(creditCardNumber.Length - 4).Mask(),
                OrderId = orderId
            };
            _context.OrderPayments.Add(orderPayment);
            _context.SaveChanges();
        }
    }

    public static class MaskExtensions
    {
        public static string Mask(this string s) { return s; }
    }
}

namespace Cwe256.MySql
{
    public class Encoder
    {
        public static string Encode(string s)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(s));
        }
    }

    public class MySqlDbProvider
    {
        // CWE-256: Base64 is the only protection before a MySQL update.
        public string UpdateCustomerPassword(int customerNumber, string password)
        {
            string sql = "update CustomerLogin set password = '" + Encoder.Encode(password) + "' where customerNumber = " + customerNumber;
            MySqlCommand command = new MySqlCommand(sql, null); // $ Alert
            command.ExecuteNonQuery();
            return null;
        }

        // Safe: lookup only.
        public bool IsValidCustomerLogin(string email, string password)
        {
            string sql = "select * from CustomerLogin where email = '" + email + "' and password = '" + Encoder.Encode(password) + "';";
            MySqlCommand command = new MySqlCommand(sql, null);
            return command.ExecuteScalar() != null;
        }
    }
}
