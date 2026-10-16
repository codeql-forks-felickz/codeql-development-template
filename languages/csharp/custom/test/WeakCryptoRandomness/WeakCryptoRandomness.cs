using System;
using System.Security.Cryptography;

namespace System.Web
{
    // Minimal stub of the ASP.NET (System.Web) cookie type.
    public class HttpCookie
    {
        public HttpCookie(string name) { }
        public HttpCookie(string name, string value) { }
        public string Value { get; set; }
    }
}

namespace Microsoft.AspNetCore.Http
{
    // Minimal stub of the ASP.NET Core response cookie collection.
    public interface IResponseCookies
    {
        void Append(string key, string value);
    }
}

namespace WeakCryptoRandomnessTests
{
    using System.Web;
    using Microsoft.AspNetCore.Http;

    public class Ticket
    {
        public string ApprovalCode { get; set; }
        public string ResetToken { get; set; }
        public DateTime TokenExpiry { get; set; }
    }

    public class SessionManager
    {
        private static int visitors = 10342;
        private readonly Random rnd = new Random();

        // Reduced from a `Session_Start` handler that builds the session id from the clock and a counter.
        public HttpCookie StartSession()
        {
            HttpCookie sessionCookie = new HttpCookie("amSessionId");
            visitors += 3;
            sessionCookie.Value = DateTime.Now.Hour.ToString() + DateTime.Now.Minute.ToString() + DateTime.Now.Second.ToString() + visitors.ToString(); // $ Alert
            return sessionCookie;
        }

        public HttpCookie AuthCookie()
        {
            return new HttpCookie("authToken", rnd.Next().ToString()); // $ Alert
        }

        public void AspNetCoreCookie(IResponseCookies cookies)
        {
            string value = DateTime.UtcNow.Ticks.ToString(); // $ Source
            cookies.Append(".App.SessionId", value); // $ Alert
        }

        public string Captcha()
        {
            string captcha = rnd.Next(1000, 9999).ToString(); // $ Alert
            return captcha;
        }

        public Ticket Approve()
        {
            var ticket = new Ticket();
            ticket.ApprovalCode = Environment.TickCount.ToString("X"); // $ Alert
            return ticket;
        }

        public void SendReset(Ticket ticket)
        {
            int seed = DateTime.Now.Millisecond; // $ Source
            ticket.ResetToken = "rt-" + seed; // $ Alert
        }

        private void Store(string sessionKey) { }

        public void ParameterSink()
        {
            var r = new Random(); // fixed seed or not, System.Random is predictable
            Store(r.NextDouble().ToString()); // $ Alert
        }

        // ---- Safe counterparts: should not be reported ----

        public HttpCookie SecureSession()
        {
            HttpCookie sessionCookie = new HttpCookie("amSessionId");
            sessionCookie.Value = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            return sessionCookie;
        }

        public string SecureCaptcha()
        {
            string captcha = RandomNumberGenerator.GetInt32(1000, 9999).ToString();
            return captcha;
        }

        public void SecureTokenWithTimestamp(Ticket ticket)
        {
            // A timestamp mixed with a cryptographically strong value is not predictable.
            ticket.ResetToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)) + DateTime.UtcNow.Ticks;
        }

        public HttpCookie LastVisitCookie()
        {
            // Not a security-sensitive cookie.
            return new HttpCookie("lastVisit", DateTime.Now.ToString());
        }

        public void TokenMetadata(Ticket ticket)
        {
            // Expiry metadata is not a secret value.
            ticket.TokenExpiry = DateTime.UtcNow.AddMinutes(30);
            int retryDelay = rnd.Next(100, 500);
        }
    }
}
