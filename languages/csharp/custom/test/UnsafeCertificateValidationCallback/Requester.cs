using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace DisableSsl
{
    internal static class Requester
    {
        private static bool IsDevelopment = false;

        public static void AnonymousMethod()
        {
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; }; // $ Alert[cs/unsafe-certificate-validation-callback]
            using WebClient client = new();
            string response = client.DownloadString("https://example.com");
        }

        public static void LambdaAddAssign()
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, errors) => true; // $ Alert[cs/unsafe-certificate-validation-callback]
        }

        public static void HttpClientHandlerProperty()
        {
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => { return true; }; // $ Alert[cs/unsafe-certificate-validation-callback]
        }

        public static void DangerousAcceptAny()
        {
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator // $ Alert[cs/unsafe-certificate-validation-callback]
            };
        }

        public static void MethodGroup()
        {
            ServicePointManager.ServerCertificateValidationCallback = AcceptAll; // $ Alert[cs/unsafe-certificate-validation-callback]
        }

        public static void ExplicitDelegateToSslStream(Stream stream)
        {
            var ssl = new SslStream(stream, false, new RemoteCertificateValidationCallback(AcceptAll)); // $ Alert[cs/unsafe-certificate-validation-callback]
        }

        public static void ViaLocalVariable()
        {
            RemoteCertificateValidationCallback callback = (sender, cert, chain, errors) => true;
            ServicePointManager.ServerCertificateValidationCallback = callback; // $ Alert[cs/unsafe-certificate-validation-callback]
        }

        public static void SslClientOptions()
        {
            var options = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (sender, cert, chain, errors) => true // $ Alert[cs/unsafe-certificate-validation-callback]
            };
        }

        private static bool AcceptAll(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
        {
            return true;
        }

        // Safe: the callback honours the platform validation result.
        public static void ValidatesErrors()
        {
            ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => errors == SslPolicyErrors.None;
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (message, c, ch, errors) => errors == SslPolicyErrors.None;
        }

        // Safe: a named method that performs validation.
        public static void ValidatingMethodGroup(Stream stream)
        {
            var ssl = new SslStream(stream, false, Validate);
        }

        private static bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
        {
            return errors == SslPolicyErrors.None;
        }

        // Safe: the callback only conditionally returns true.
        public static void Conditional()
        {
            ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
            {
                if (IsDevelopment)
                    return true;
                return errors == SslPolicyErrors.None;
            };
        }

        // Safe: an unrelated always-true delegate.
        public static void Unrelated()
        {
            Func<int, bool> always = x => true;
            Predicate<string> p = AlwaysTrue;
        }

        private static bool AlwaysTrue(string s) => true;
    }
}
