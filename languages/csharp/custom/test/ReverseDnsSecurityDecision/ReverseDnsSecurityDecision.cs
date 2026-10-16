using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace ReverseDnsSecurityDecisionTests
{
    public class HostAuthorizer
    {
        private readonly HashSet<string> trustedHosts = new HashSet<string> { "trustme.example.com" };

        private static void Log(string message) => Console.WriteLine(message);

        private static void GrantAccess() { }

        // Reduced from a test case that grants access based on the reverse DNS name of the client.
        public void Bad()
        {
            string secretHostname = "www.domain.example";
            IPAddress hostIPAddress = IPAddress.Parse("127.0.0.1");
            IPHostEntry hostInfo = Dns.GetHostEntry(hostIPAddress); // $ Source
            if (hostInfo.HostName.Equals(secretHostname)) // $ Alert
            {
                Console.WriteLine("Access granted.");
            }
        }

        public bool IsTrusted(IPAddress client)
        {
            string name = Dns.GetHostEntry(client).HostName; // $ Source
            return name.EndsWith(".corp.example.com", StringComparison.OrdinalIgnoreCase); // $ Alert
        }

        public void Allowlist(IPAddress client)
        {
            var entry = Dns.GetHostByAddress(client); // $ Source
            if (trustedHosts.Contains(entry.HostName)) // $ Alert
            {
                GrantAccess();
            }
        }

        public async Task AsyncLookup(IPAddress client)
        {
            IPHostEntry entry = await Dns.GetHostEntryAsync(client); // $ Source
            if (entry.HostName == "admin.example.com") // $ Alert
            {
                GrantAccess();
            }
        }

        public bool AliasTrusted(IPAddress client)
        {
            foreach (string alias in Dns.GetHostEntry(client).Aliases) // $ Source
            {
                if (alias == "trusted.example.com") // $ Alert
                {
                    return true;
                }
            }
            return false;
        }

        // ---- Safe counterparts: should not be reported ----

        public void OnlyLogsHostName()
        {
            string secretHostname = "www.domain.example";
            IPAddress hostIPAddress = IPAddress.Parse("127.0.0.1");
            IPHostEntry hostInfo = Dns.GetHostEntry(hostIPAddress);
            // The resolved name is only recorded, no security decision is made.
            if (hostInfo.HostName.Equals(secretHostname))
            {
                Log(hostInfo.HostName);
            }
        }

        public void ForwardLookup()
        {
            // Forward lookup of a host name the application chose.
            IPHostEntry entry = Dns.GetHostEntry("api.example.com");
            if (entry.HostName == "api.example.com")
            {
                GrantAccess();
            }
        }

        public void LogOnly(IPAddress client)
        {
            Log("Client: " + Dns.GetHostEntry(client).HostName);
        }

        public void IpAllowlist(IPAddress client)
        {
            // Decision based on the address itself rather than on its reverse DNS name.
            if (client.Equals(IPAddress.Loopback))
            {
                GrantAccess();
            }
        }
    }
}
