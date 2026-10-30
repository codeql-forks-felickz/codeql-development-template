// Minimal stubs for the JWT libraries used by the test cases.

namespace Microsoft.IdentityModel.Tokens
{
    public static class Base64UrlEncoder
    {
        public static string Decode(string arg) => null;
        public static byte[] DecodeBytes(string str) => null;
    }

    public class TokenValidationParameters
    {
        public bool ValidateIssuerSigningKey { get; set; }
        public SecurityKey IssuerSigningKey { get; set; }
    }

    public abstract class SecurityKey { }

    public class SymmetricSecurityKey : SecurityKey
    {
        public SymmetricSecurityKey(byte[] key) { }
    }

    public abstract class SecurityToken { }
}

namespace System.IdentityModel.Tokens.Jwt
{
    using Microsoft.IdentityModel.Tokens;
    using Stubs;

    public class JwtSecurityTokenHandler
    {
        public ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            validatedToken = null;
            return null;
        }
    }
}

namespace Stubs
{
    public class ClaimsPrincipal
    {
        public string FindFirstValue(string type) => null;
    }

    public class JsonObject
    {
        public static JsonObject Parse(string json) => null;
        public string GetString(string name) => null;
        public string[] GetStrings(string name) => null;
    }

    public static class Hmac
    {
        public static byte[] Sign(byte[] key, string data) => null;
        public static bool FixedTimeEquals(byte[] a, byte[] b) => false;
    }
}
