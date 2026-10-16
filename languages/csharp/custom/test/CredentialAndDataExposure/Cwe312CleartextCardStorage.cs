using System;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using Microsoft.EntityFrameworkCore;

namespace Cwe312.Models
{
    public class OrderPayment
    {
        public int OrderId { get; set; }
        public string CreditCardNumber { get; set; }
        public string MaskedCardNumber { get; set; }
        public DateTime ExpirationDate { get; set; }
        public string ApprovalCode { get; set; }
    }

    public class StoreContext : DbContext
    {
        public DbSet<OrderPayment> OrderPayments { get; set; }
    }

    public class CardVault
    {
        public static string Encrypt(string value) { return value; }
    }

    public class OrderRepository
    {
        private readonly StoreContext _context;

        public OrderRepository(StoreContext context) { _context = context; }

        // CWE-312: full card number persisted in cleartext.
        public void CreateOrderPayment(int orderId, string creditCardNumber, DateTime expirationDate, string approvalCode)
        {
            var orderPayment = new OrderPayment()
            {
                CreditCardNumber = creditCardNumber, // $ Alert
                ApprovalCode = approvalCode,
                ExpirationDate = expirationDate,
                OrderId = orderId
            };
            _context.OrderPayments.Add(orderPayment);
            _context.SaveChanges();
        }

        // Safe: card number encrypted / masked before persisting.
        public void CreateOrderPaymentProtected(int orderId, string creditCardNumber)
        {
            var orderPayment = new OrderPayment();
            orderPayment.OrderId = orderId;
            orderPayment.CreditCardNumber = CardVault.Encrypt(creditCardNumber);
            orderPayment.MaskedCardNumber = "************" + creditCardNumber.Substring(creditCardNumber.Length - 4);
            _context.OrderPayments.Add(orderPayment);
            _context.SaveChanges();
        }
    }

    public class CreditCard
    {
        public string Filename { get; set; }
        public string Username { get; set; }
        public string Number { get; set; }
        public DateTime Expiry { get; set; }

        private XDocument ReadCreditCardFile()
        {
            return XDocument.Load(Filename);
        }

        private void WriteCreditCardFile(XDocument xmlDocument)
        {
            using (var writeStream = File.Open(Filename, FileMode.Create))
            {
                var writer = new StreamWriter(writeStream);
                xmlDocument.Save(writer);
                writer.Close();
            }
        }

        // CWE-312: card number written to an XML file in cleartext.
        public void InsertCardForUser()
        {
            XDocument document = ReadCreditCardFile();
            var root = document.Root;
            root.Add(new XElement("CreditCard",
                new XElement("Username", Username),
                new XElement("Number", Number), // $ Alert
                new XElement("Expiry", Expiry)));
            WriteCreditCardFile(document);
        }

        // CWE-312: update of an existing card entry.
        public void UpdateCardForUser()
        {
            XDocument document = ReadCreditCardFile();
            var ccElement = document.Descendants("CreditCard").FirstOrDefault();
            var numberElement = ccElement.Element("Number");
            numberElement.Value = Number; // $ Alert
            WriteCreditCardFile(document);
        }

        // Safe: only the user name is written.
        public void InsertUser()
        {
            XDocument document = ReadCreditCardFile();
            document.Root.Add(new XElement("Username", Username));
            WriteCreditCardFile(document);
        }
    }
}
