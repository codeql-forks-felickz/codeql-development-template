using System;
using System.Net;

// Reduced from the Juliet C# 1.3 CWE350 `GetHostEntry_01` test case.
public class JulietReverseDns
{
    public void Bad()
    {
        string secretHostname = "www.domain.nonexistenttld";
        IPAddress hostIPAddress = IPAddress.Parse("127.0.0.1");
        IPHostEntry hostInfo = Dns.GetHostEntry(hostIPAddress);
        // The guarded action only prints a message, which is not modeled as a sensitive
        // action by `cs/user-controlled-bypass`, so the condition is not a sink.
        if (hostInfo.HostName.Equals(secretHostname)) // $ MISSING: Alert
        {
            Console.WriteLine("Access granted.");
        }
    }

    // Same source, but the guarded action is an authorization method.
    public void BadWithAuthorize(string user)
    {
        string secretHostname = "www.domain.nonexistenttld";
        IPAddress hostIPAddress = IPAddress.Parse("127.0.0.1");
        IPHostEntry hostInfo = Dns.GetHostEntry(hostIPAddress); // $ Source=j1
        if (hostInfo.HostName.Equals(secretHostname)) // $ Alert=j1
        {
            AuthorizeUser(user);
        }
    }

    public void Good()
    {
        string secretHostname = "www.domain.nonexistenttld";
        IPAddress hostIPAddress = IPAddress.Parse("127.0.0.1");
        IPHostEntry hostInfo = Dns.GetHostEntry(hostIPAddress);
        if (hostInfo.HostName.Equals(secretHostname))
        {
            Console.WriteLine(hostInfo.HostName);
        }
    }

    private static void AuthorizeUser(string user) { }
}
