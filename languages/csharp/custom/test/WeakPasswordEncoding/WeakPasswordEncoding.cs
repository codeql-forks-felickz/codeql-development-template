using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace WeakPasswordEncodingTests
{
    public class DbSettings
    {
        public string Password { get; set; }
    }

    public class Credentials
    {
        // Reduced from a test case that reads a Base64-"protected" password from a file.
        public NetworkCredential FromFile()
        {
            StreamReader sr = new StreamReader("weak_password_file.txt");
            string password = sr.ReadLine();
            string decPass = Encoding.UTF8.GetString(Convert.FromBase64String(password)); // $ Source
            return new NetworkCredential("user", decPass, ""); // $ Alert
        }

        public void FromAllText(DbSettings settings)
        {
            byte[] raw = Convert.FromBase64String(File.ReadAllText("db.secret")); // $ Source
            settings.Password = Encoding.UTF8.GetString(raw); // $ Alert
        }

        public NetworkCredential FromHardcodedLiteral()
        {
            return new NetworkCredential("svc", Encoding.ASCII.GetString(Convert.FromBase64String("cDRzc3cwcmQ="))); // $ Alert
        }

        public void FromRegistry(DbSettings settings)
        {
            string stored = (string)Registry.GetValue(@"HKEY_CURRENT_USER\Software\App", "pwd", null);
            settings.Password = Encoding.UTF8.GetString(Convert.FromBase64String(stored)); // $ Alert
        }

        // ---- Safe counterparts: should not be reported ----

        public NetworkCredential FromEncryptedFile()
        {
            byte[] encryptedPassword = Convert.FromBase64String(File.ReadAllText("strong_password_file.txt"));
            string decPass;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes("ABCDEFGHABCDEFGH");
                aesAlg.IV = new byte[16];
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(encryptedPassword))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    decPass = srDecrypt.ReadToEnd();
                }
            }
            return new NetworkCredential("user", decPass, "");
        }

        public NetworkCredential FromDpapiWrapper()
        {
            byte[] blob = Convert.FromBase64String(File.ReadAllText("dpapi.bin"));
            return new NetworkCredential("user", Decrypt(blob));
        }

        private static string Decrypt(byte[] blob)
        {
            return Encoding.UTF8.GetString(ProtectedDataStub.Unprotect(blob));
        }

        public bool BasicAuth(string authorizationHeader)
        {
            // Base64 decoding of an HTTP Basic credential received from the client is expected.
            string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(authorizationHeader.Substring(6)));
            return Validate("user", decoded.Split(':')[1]);
        }

        private static bool Validate(string user, string password) => password.Length > 0;

        public byte[] NotAPassword()
        {
            // Base64-decoded data that is never used as a password.
            return Convert.FromBase64String(File.ReadAllText("image.b64"));
        }
    }

    public static class ProtectedDataStub
    {
        public static byte[] Unprotect(byte[] data) => data;
    }
}
