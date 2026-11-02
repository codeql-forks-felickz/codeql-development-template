namespace System.Web
{
    public class HttpResponse
    {
        public void Redirect(string url) { }
        public void Redirect(string url, bool endResponse) { }
        public void End() { }
        public void Write(string s) { }
    }

    public class HttpContext
    {
        public static HttpContext Current => null;
        public SessionState.HttpSessionState Session => null;
        public HttpResponse Response => null;
    }

    public class HttpApplication
    {
        public void CompleteRequest() { }
    }
}

namespace System.Web.SessionState
{
    public class HttpSessionState
    {
        public int Timeout { get; set; }
    }
}

namespace Microsoft.AspNetCore.Http
{
    public abstract class HttpResponse
    {
        public virtual void Redirect(string location) { }
        public abstract void Redirect(string location, bool permanent);
    }
}

namespace Microsoft.AspNetCore.Identity
{
    public class PasswordOptions
    {
        public int RequiredLength { get; set; }
        public bool RequireDigit { get; set; }
        public bool RequireNonAlphanumeric { get; set; }
    }

    public class LockoutOptions
    {
        public bool AllowedForNewUsers { get; set; }
        public int MaxFailedAccessAttempts { get; set; }
    }

    public class IdentityOptions
    {
        public PasswordOptions Password { get; set; }
        public LockoutOptions Lockout { get; set; }
    }
}

namespace Microsoft.IdentityModel.Tokens
{
    public class TokenValidationParameters
    {
        public bool ValidateIssuer { get; set; }
        public bool ValidateAudience { get; set; }
        public bool ValidateLifetime { get; set; }
        public bool RequireSignedTokens { get; set; }
        public bool RequireExpirationTime { get; set; }
        public bool ValidateIssuerSigningKey { get; set; }
        public string ValidIssuer { get; set; }
    }
}
