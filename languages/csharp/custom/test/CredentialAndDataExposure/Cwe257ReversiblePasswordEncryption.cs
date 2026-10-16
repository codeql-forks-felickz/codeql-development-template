using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Cwe257
{
    public class CryptographicService
    {
        private const string Key = "KIhVazAM9PcciXgyN2an/Vkp4bytF+B/INSbBrQSTmY=";

        public string HashPassword(string password, string salt)
        {
            return UnsafeStorage(password, salt);
        }

        // CWE-257: the password is AES-encrypted (reversible) rather than hashed.
        private static string UnsafeStorage(string password, string salt)
        {
            using (var aes = Aes.Create())
            {
                aes.IV = System.Text.Encoding.UTF8.GetBytes(salt).Take(16).ToArray();
                aes.Key = Convert.FromBase64String(Key);
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(password); // $ Alert
                        }
                    }
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }

        // CWE-257: same, through ICryptoTransform.TransformFinalBlock.
        public static byte[] EncryptPassword(string userPassword, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                ICryptoTransform enc = aes.CreateEncryptor(key, iv);
                byte[] data = System.Text.Encoding.UTF8.GetBytes(userPassword);
                return enc.TransformFinalBlock(data, 0, data.Length); // $ Alert
            }
        }

        // Safe: a salted, adaptive hash.
        private static string SafeStorage(string password, string salt, int iterations)
        {
            byte[] saltBytes = Convert.FromBase64String(salt);
            using (var hash = new Rfc2898DeriveBytes(password, saltBytes, iterations, HashAlgorithmName.SHA256))
            {
                return Convert.ToBase64String(hash.GetBytes(20));
            }
        }

        // Safe: non-credential data is encrypted.
        public static string EncryptNote(string note, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cs))
            {
                sw.Write(note);
                return Convert.ToBase64String(ms.ToArray());
            }
        }

        // Safe: decrypting is not storing a password.
        public static string Decrypt(byte[] cipher, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            using (var ms = new MemoryStream(cipher))
            using (var cs = new CryptoStream(ms, aes.CreateDecryptor(key, iv), CryptoStreamMode.Read))
            using (var sr = new StreamReader(cs))
            {
                return sr.ReadToEnd();
            }
        }
    }
}
