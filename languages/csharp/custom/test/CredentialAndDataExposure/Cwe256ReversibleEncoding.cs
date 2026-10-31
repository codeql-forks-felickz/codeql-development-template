using System;
using System.Text;
using System.Security.Cryptography;
using System.Web;
using Mono.Data.Sqlite;

namespace Cwe256
{
    public class Encoder
    {
        public static string Encode(string s)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(s);
            string output = Convert.ToBase64String(bytes);
            return output;
        }
    }

    public class SqliteDbProvider
    {
        private string _connectionString;

        // CWE-256: Base64 is the only "protection" applied to the stored password.
        public string UpdateCustomerPassword(int customerNumber, string password)
        {
            string sql = "update CustomerLogin set password = '" + Encoder.Encode(password) + "' where customerNumber = " + customerNumber;
            using (SqliteConnection connection = new SqliteConnection(_connectionString))
            {
                SqliteCommand command = new SqliteCommand(sql, connection); // $ Alert
                command.ExecuteNonQuery();
            }
            return null;
        }

        // CWE-256: inline Convert.ToBase64String.
        public void AddCustomer(string email, string password)
        {
            string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(password));
            var command = new SqliteCommand("insert into CustomerLogin (email, password) values ('" + email + "', '" + encoded + "')", null); // $ Alert
            command.ExecuteNonQuery();
        }

        // Safe: the password is hashed with a salted, slow KDF before being Base64 encoded.
        public void AddCustomerHashed(string email, string password, byte[] salt)
        {
            string hashed = Convert.ToBase64String(new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256).GetBytes(32));
            var command = new SqliteCommand("insert into CustomerLogin (email, password) values ('" + email + "', '" + hashed + "')", null);
            command.ExecuteNonQuery();
        }

        // Safe: a lookup (not a store) of the encoded password.
        public bool IsValidCustomerLogin(string email, string password)
        {
            string sql = "select * from CustomerLogin where email = '" + email + "' and password = '" + Encoder.Encode(password) + "';";
            var command = new SqliteCommand(sql, null);
            return command.ExecuteScalar() != null;
        }
    }
}

namespace Cwe315
{
    // A hand-rolled Base64 encoder (no call to Convert.ToBase64String).
    public class Base64Encoder
    {
        private byte[] source;

        public Base64Encoder(string sInput)
        {
            source = Encoding.UTF8.GetBytes(sInput);
        }

        public string GetEncoded()
        {
            char[] result = new char[source.Length * 2];
            for (int x = 0; x < source.Length; x++)
            {
                result[x] = (char)('A' + (source[x] & 63));
            }
            StringBuilder sb = new StringBuilder();
            sb.Append(result);
            return sb.ToString();
        }
    }

    public class Authentication : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            String uname = Request.Params["uid"];
            String passwd = Request.Params["passw"];
            ValidateUser(uname, passwd);
        }

        protected string ValidateUser(String uName, String pWord)
        {
            // CWE-315: the password is stored in a cookie after only Base64 encoding.
            HttpCookie userInfo = new HttpCookie("amUserInfo");
            userInfo["UserName"] = new Base64Encoder(uName).GetEncoded();
            userInfo["Password"] = new Base64Encoder(pWord).GetEncoded(); // $ Alert
            Response.Cookies.Add(userInfo);
            return "Success";
        }

        // Safe: the cookie only carries a non-sensitive value.
        protected void RememberUser(string userName)
        {
            HttpCookie c = new HttpCookie("amUserName");
            c.Value = new Base64Encoder(userName).GetEncoded();
            Response.Cookies.Add(c);
        }
    }
}
