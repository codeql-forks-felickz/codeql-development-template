using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Stubs;

namespace JwtTests
{
    public class JwtPayload
    {
        public string Username { get; set; }
        public IList<string> Roles { get; set; }

        // BAD: the payload segment is base64-decoded and its claims are trusted
        // without ever checking the token signature.
        public static JwtPayload ParseJwt(string jwt)
        {
            var jwtPayloadBase64 = jwt.Split('.')[1]; // $ Source
            if (jwtPayloadBase64.Length % 4 != 0)
            {
                jwtPayloadBase64 = jwtPayloadBase64.PadRight(jwtPayloadBase64.Length + (4 - jwtPayloadBase64.Length % 4), '=');
            }

            var json = Encoding.UTF8.GetString(Convert.FromBase64String(jwtPayloadBase64)); // $ Alert
            var doc = JsonObject.Parse(json);
            return new JwtPayload
            {
                Username = doc.GetString("username"),
                Roles = doc.GetStrings("roles")
            };
        }
    }

    public class AuthService
    {
        // BAD: base64url payload normalized with Replace before decoding.
        public bool IsAdmin(string token)
        {
            var parts = token.Split(".");
            var payload = parts[1].Replace('-', '+').Replace('_', '/'); // $ Source
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload)); // $ Alert
            return json.Contains("\"role\":\"admin\"");
        }

        // BAD: Base64UrlEncoder.Decode on the payload segment.
        public string GetSubject(string token)
        {
            string[] parts = token.Split('.');
            var json = Base64UrlEncoder.Decode(parts[1]); // $ Alert
            var doc = JsonObject.Parse(json);
            return doc.GetString("sub");
        }

        // BAD: the payload segment reaches the decoder through a helper method.
        public string GetRoleViaHelper(string token)
        {
            var segments = token.Split('.');
            var json = DecodeSegment(segments[1]); // $ Source
            var doc = JsonObject.Parse(json);
            return doc.GetString("role");
        }

        private static string DecodeSegment(string segment)
        {
            var padded = segment.PadRight(segment.Length + (4 - segment.Length % 4) % 4, '=');
            return Encoding.UTF8.GetString(Convert.FromBase64String(padded)); // $ Alert
        }

        // GOOD: only the header segment is decoded (e.g. to read the "kid").
        public string GetKeyId(string token)
        {
            var parts = token.Split('.');
            var header = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[0]));
            var doc = JsonObject.Parse(header);
            return doc.GetString("kid");
        }

        // GOOD: the signature segment is verified before the payload is decoded.
        public string GetRoleVerified(string token, byte[] key)
        {
            var parts = token.Split('.');
            var expected = Hmac.Sign(key, parts[0] + "." + parts[1]);
            var actual = Base64UrlEncoder.DecodeBytes(parts[2]);
            if (!Hmac.FixedTimeEquals(expected, actual))
            {
                throw new UnauthorizedAccessException();
            }
            var json = Base64UrlEncoder.Decode(parts[1]);
            var doc = JsonObject.Parse(json);
            return doc.GetString("role");
        }

        // GOOD: the token is validated by a JWT library and claims are read from the result.
        public string GetRoleValidated(string token, byte[] key)
        {
            var handler = new JwtSecurityTokenHandler();
            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };
            ClaimsPrincipal principal = handler.ValidateToken(token, parameters, out _);
            return principal.FindFirstValue("role");
        }

        // GOOD: not a JWT; the string is not split on '.'.
        public byte[] DecodeSecondField(string csv)
        {
            var fields = csv.Split(',');
            return Convert.FromBase64String(fields[1]);
        }
    }
}
