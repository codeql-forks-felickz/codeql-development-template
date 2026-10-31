using System.Security.Cryptography;

namespace HardcodedInitializationVectorTests
{
    public class Cipher
    {
        public void Bad()
        {
            using (Aes aes = Aes.Create())
            {
                aes.IV = new byte[16]; // $ Alert
            }
        }

        public void Good()
        {
            using (Aes aes = Aes.Create())
            {
                aes.IV = RandomNumberGenerator.GetBytes(16);
            }
        }
    }
}
