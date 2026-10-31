using System.Data.SqlClient;

namespace Cwe256Insert
{
    public class LookalikeParameterCollection
    {
        public void AddWithValue(string name, object value) { }
    }

    public class AccountSeeder
    {
        private readonly string connectionString = @"127.0.0.1\sql";

        // CWE-256: a plaintext (hard-coded) password is inserted into the user table.
        public void SeedAdmin()
        {
            string query = "INSERT INTO Users (Username, Password) VALUES (@Username, @Password)";
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@Username", "newAdmin");
                command.Parameters.AddWithValue("@Password", "TheAdminP@ssw0rd"); // $ Alert
                connection.Open();
                command.ExecuteNonQuery();
            }
        }

        // CWE-256: the user-supplied password is stored verbatim.
        public void Register(string username, string password)
        {
            string query = "INSERT INTO Users (Username, Password) VALUES (@Username, @Password)";
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@Username", username);
                command.Parameters.Add(new SqlParameter("@Password", password)); // $ Alert
                command.ExecuteNonQuery();
            }
        }

        // Safe: the password is hashed before it is stored.
        public void RegisterHashed(string username, string password)
        {
            string query = "INSERT INTO Users (Username, Password) VALUES (@Username, @Password)";
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@Username", username);
                command.Parameters.AddWithValue("@Password", HashPassword(password));
                command.ExecuteNonQuery();
            }
        }

        // CWE-256: a plaintext password is inserted through CommandText assignment.
        public void RegisterWithCommandText(string password)
        {
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                SqlCommand command = new SqlCommand("", connection);
                command.CommandText = "INSERT INTO Users (Password) VALUES (@Password)";
                command.Parameters.AddWithValue("@Password", password); // $ Alert
                command.ExecuteNonQuery();
            }
        }

        // Safe: the password is only used to look up a row, not stored.
        public void Find(string username, string password)
        {
            string query = "SELECT * FROM Users WHERE Username = @Username AND Password = @Password";
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@Password", password);
                command.ExecuteReader();
            }
        }

        // Safe: the password is bound to a SELECT even though the method also writes an audit row.
        public void FindAndAudit(string username, string password)
        {
            string query = "SELECT * FROM Users WHERE Username = @Username AND Password = @Password";
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@Password", password);
                command.ExecuteReader();

                SqlCommand audit = new SqlCommand("INSERT INTO AuditLog (Action) VALUES (@Action)", connection);
                audit.Parameters.AddWithValue("@Action", "lookup");
                audit.ExecuteNonQuery();
            }
        }

        // Safe: an unrelated method named AddWithValue does not bind a SQL parameter.
        public void UseLookalikeParameterCollection(string password)
        {
            string query = "INSERT INTO Users (Password) VALUES (@Password)";
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                SqlCommand command = new SqlCommand(query, connection);
                new LookalikeParameterCollection().AddWithValue("@Password", password);
                command.ExecuteNonQuery();
            }
        }

        private static string HashPassword(string password) { return password.GetHashCode().ToString(); }
    }
}
