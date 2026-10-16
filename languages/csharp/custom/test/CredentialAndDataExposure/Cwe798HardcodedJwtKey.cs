using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Cwe798
{
    public class User
    {
        public const string TokenSecret = "f449a71cff1d56a122c84fa478c16af9075e5b4b8527787b56580773242e40ce";

        // CWE-798: JWT signing key embedded in source.
        public SecurityKey CreateSigningKey()
        {
            string secret = TokenSecret;
            return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)); // $ Alert
        }

        // CWE-798: direct literal.
        public SecurityKey CreateSigningKeyInline()
        {
            return new SymmetricSecurityKey(Encoding.ASCII.GetBytes("super-secret-signing-key-0123456789")); // $ Alert
        }

        // CWE-798: byte array literal.
        public SecurityKey CreateSigningKeyBytes()
        {
            return new SymmetricSecurityKey(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }); // $ Alert
        }

        // Safe: key supplied by configuration / secret store at runtime.
        public SecurityKey CreateSigningKeyFromConfig(string configuredKey)
        {
            return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuredKey));
        }

        // Safe: key read from the environment.
        public SecurityKey CreateSigningKeyFromEnvironment()
        {
            return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(System.Environment.GetEnvironmentVariable("JWT_KEY")));
        }
    }
}
