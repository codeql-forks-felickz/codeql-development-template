using System;
using System.Diagnostics;

namespace CommandLineInjectionLocalTests
{
    // Reduced from a console app that interpolates a command-line argument into `cmd.exe /C`.
    public class Program
    {
        public static void Main(string[] args)
        {
            string parameter = Environment.GetCommandLineArgs()[1]; // $ Source
            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = $"/C {parameter}"; // $ Alert
            process.Start();
        }

        // GOOD: the command line is constant.
        public static void Good()
        {
            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/C dir";
            process.Start();
        }
    }
}
