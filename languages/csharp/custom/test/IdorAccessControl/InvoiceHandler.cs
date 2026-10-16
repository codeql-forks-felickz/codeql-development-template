using System;
using System.Data;
using System.Data.SqlClient;
using System.Web;

namespace Invoices
{
    public class InvoiceHandler
    {
        // The record key comes straight from the `id` URL parameter.
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            string data = req.Params.Get("id"); // $ Source
            int id;
            try
            {
                id = int.Parse(data);
            }
            catch (FormatException)
            {
                id = -1;
            }
            using (SqlCommand preparedStatement = new SqlCommand(null, new SqlConnection()))
            {
                preparedStatement.CommandText = "select * from invoices where uid=@id";
                SqlParameter idParam = new SqlParameter("@id", SqlDbType.Int, 0);
                idParam.Value = id; // $ Alert
                preparedStatement.ExecuteNonQuery();
            }
        }

        // Hard-coded key: no user-controlled object reference.
        public void GoodG2B(HttpRequest req, HttpResponse resp)
        {
            string data = "10";
            int id = int.Parse(data);
            using (SqlCommand preparedStatement = new SqlCommand(null, new SqlConnection()))
            {
                preparedStatement.CommandText = "select * from invoices where uid=@id";
                SqlParameter idParam = new SqlParameter("@id", SqlDbType.Int, 0);
                idParam.Value = id;
                preparedStatement.ExecuteNonQuery();
            }
        }
    }
}
