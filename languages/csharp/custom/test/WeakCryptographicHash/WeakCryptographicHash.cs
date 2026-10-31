using System;
using System.Security.Cryptography;
using System.Text;

namespace WeakCryptographicHashTests
{
    public class Credentials
    {
        private static void StoreSecret(string secret) { }
        private static void StorePasswordHash(string passwordHash) { }
        private static void StoreChecksum(string checksum) { }

        public void Md5Secret(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input)); // $ Source
                string secret = Convert.ToBase64String(hash); // $ Alert
                StoreSecret(secret);
            }
        }

        public void UnsaltedPasswordHash(string password)
        {
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(password)); // $ Source
            string passwordHash = Convert.ToBase64String(hash); // $ Alert
            StorePasswordHash(passwordHash);
        }

        public void ModernChecksum(string input)
        {
            string checksum = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
            StoreChecksum(checksum);
        }

        public void Md5Checksum(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                string checksum = Convert.ToBase64String(
                    md5.ComputeHash(Encoding.UTF8.GetBytes(input))
                );
                StoreChecksum(checksum);
            }
        }
    }
}
