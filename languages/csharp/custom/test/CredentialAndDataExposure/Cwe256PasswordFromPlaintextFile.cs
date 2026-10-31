using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Cwe256File
{
    public class DatabaseConnector
    {
        // CWE-256: the database password is read from a plaintext file and used directly.
        public void Bad()
        {
            string password = "";
            try
            {
                password = Encoding.UTF8.GetString(File.ReadAllBytes("../../../common/strong_password_file.txt"));
            }
            catch (IOException)
            {
            }
            using (SqlConnection dBConnection = new SqlConnection(@"Data Source=(local);Initial Catalog=CWE256;User ID=" + "sa" + ";Password=" + password)) // $ Alert
            {
                dBConnection.Open();
            }
        }

        // CWE-256: same, with string interpolation.
        public void BadInterpolated()
        {
            string password = File.ReadAllText("db_password.txt");
            using (SqlConnection dBConnection = new SqlConnection($"Server=db;User ID=sa;Password={password}")) // $ Alert
            {
                dBConnection.Open();
            }
        }

        // Safe: the password file is encrypted and decrypted before use.
        public void Good()
        {
            string password = "";
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes("ABCDEFGHABCDEFGH");
                aesAlg.IV = new byte[16];
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(File.ReadAllBytes("../../../common/strong_password_file.txt")))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    password = srDecrypt.ReadToEnd();
                }
            }
            using (SqlConnection dBConnection = new SqlConnection(@"Data Source=(local);User ID=sa;Password=" + password))
            {
                dBConnection.Open();
            }
        }

        // Safe: a non-credential value read from a file.
        public void GoodCatalog()
        {
            string catalog = File.ReadAllText("catalog.txt");
            using (SqlConnection dBConnection = new SqlConnection("Data Source=(local);Initial Catalog=" + catalog))
            {
                dBConnection.Open();
            }
        }
    }
}
