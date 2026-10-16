using System;
using System.Data;
using System.Text;
using Mono.Data.Sqlite;

namespace Cwe257Recovery
{
    public static class Encoder
    {
        public static string Decode(string value) { return Encoding.UTF8.GetString(Convert.FromBase64String(value)); }
    }

    public class CustomerStore
    {
        private readonly string _connectionString = "Data Source=goat.sqlite";

        // CWE-257: the stored password is decoded and returned to the caller.
        public string GetPasswordByEmail(string email)
        {
            string result = string.Empty;
            using (SqliteConnection connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                string sql = "select * from CustomerLogin where email = '" + email + "';";
                SqliteDataAdapter da = new SqliteDataAdapter(sql, connection);
                DataSet ds = new DataSet();
                da.Fill(ds);
                string encoded_password = ds.Tables[0].Rows[0]["Password"].ToString();
                string decoded_password = Encoder.Decode(encoded_password); // $ Alert
                result = decoded_password;
            }
            return result;
        }

        // Safe: a non-credential column is decoded.
        public string GetAvatar(string email)
        {
            using (SqliteConnection connection = new SqliteConnection(_connectionString))
            {
                SqliteDataAdapter da = new SqliteDataAdapter("select * from CustomerLogin", connection);
                DataSet ds = new DataSet();
                da.Fill(ds);
                return Encoder.Decode(ds.Tables[0].Rows[0]["avatar"].ToString());
            }
        }

        // Safe: the stored hash is only compared, never decoded.
        public bool Verify(DataRow row, string candidateHash)
        {
            return row["Password"].ToString() == candidateHash;
        }
    }
}
