using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace UntrustedSearchPathTests
{
    public class Test
    {
        // Reduced from the Juliet CWE426_Untrusted_Search_Path__Process_01 test case.
        public void Bad()
        {
            string badOsCommand;
            string commandArgs;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                badOsCommand = "ls"; // $ Source=ls
                commandArgs = "-la";
            }
            else
            {
                badOsCommand = "cmd.exe"; // $ Source=cmd
                commandArgs = "/C dir";
            }
            using (Process process = new Process())
            {
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = badOsCommand; // $ Alert=ls Alert=cmd
                startInfo.Arguments = commandArgs;
                process.StartInfo = startInfo;
                process.StartInfo.UseShellExecute = false;
                process.Start();
            }
        }

        public void Good()
        {
            string goodOsCommand;
            string commandArgs;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                goodOsCommand = "/bin/ls";
                commandArgs = "-la";
            }
            else
            {
                goodOsCommand = "c:\\windows\\system32\\cmd.exe";
                commandArgs = "/C dir";
            }
            using (Process process = new Process())
            {
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = goodOsCommand;
                startInfo.Arguments = commandArgs;
                process.StartInfo = startInfo;
                process.StartInfo.UseShellExecute = false;
                process.Start();
            }
        }

        public void BadProcessStart()
        {
            Process.Start("whoami"); // $ Alert
            Process.Start("ping", "-c 1 localhost"); // $ Alert
            Process.Start("python3.11"); // $ Alert
            Process.Start("RUN.BAT"); // $ Alert
        }

        public void BadProcessStartInfo()
        {
            var psi1 = new ProcessStartInfo("git", "status"); // $ Alert
            Process.Start(psi1);
            var psi2 = new ProcessStartInfo { FileName = "netstat" }; // $ Alert
            Process.Start(psi2);
        }

        public void BadViaHelper()
        {
            Run("hostname"); // $ Source=hostname
        }

        private static void Run(string program)
        {
            Process.Start(program); // $ Alert=hostname
        }

        public void GoodQualified()
        {
            Process.Start("/usr/bin/whoami");
            Process.Start(@"C:\Windows\System32\PING.EXE", "localhost");
            Process.Start("./tool");
            Process.Start(".\\tool.exe");
            var psi = new ProcessStartInfo(Environment.ExpandEnvironmentVariables("%SystemRoot%\\System32\\cmd.exe"));
            Process.Start(psi);
        }

        public void GoodNotAnExecutable()
        {
            // Documents and URLs are opened through file associations, not the search path.
            Process.Start(new ProcessStartInfo("readme.txt") { UseShellExecute = true });
            Process.Start(new ProcessStartInfo("https://example.com") { UseShellExecute = true });
            Process.Start("");
        }
    }
}
