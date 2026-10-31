using System.Security.Cryptography;
using System.Text;

namespace Cwe916
{
    public class PasswordStore
    {
        public byte[] HashFast(string password)
        {
            using (MD5 md5 = MD5.Create())
            {
                return md5.ComputeHash(Encoding.UTF8.GetBytes(password)); // $ Alert
            }
        }

        public byte[] HashWithPbkdf2(string password, byte[] salt)
        {
            using (var hash = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256))
            {
                return hash.GetBytes(32);
            }
        }
    }
}
