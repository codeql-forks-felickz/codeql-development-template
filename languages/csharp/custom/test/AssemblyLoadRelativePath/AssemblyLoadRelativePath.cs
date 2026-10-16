using System;
using System.IO;
using System.Reflection;

namespace AssemblyLoadRelativePathTests
{
    // Reduced from a Juliet CWE-114/CWE-426 test case.
    public class ProcessControl
    {
        public void Bad()
        {
            string libraryName = "test.dll";
            Assembly.Load(libraryName); // $ Alert
        }

        public void BadInline()
        {
            Assembly.LoadFrom("plugins/test.dll"); // $ Alert
            Assembly.UnsafeLoadFrom("test.dll"); // $ Alert
#pragma warning disable 618
            Assembly.LoadWithPartialName("test.exe"); // $ Alert
#pragma warning restore 618
        }

        private const string PluginFile = "plugin.dll";

        public void BadConstant()
        {
            Assembly.LoadFrom(PluginFile); // $ Alert
        }

        // GOOD: `LoadFrom` with a fully qualified path built from a trusted root.
        public void Good1()
        {
            int p = (int)Environment.OSVersion.Platform;
            string root;
            string libraryName = "test.dll";
            if (p == (int)PlatformID.Win32NT)
            {
                root = "C:\\libs\\";
            }
            else
            {
                root = "/home/user/libs/";
            }
            Assembly.LoadFrom(root + libraryName);
        }

        // GOOD: absolute paths.
        public void Good2()
        {
            Assembly.LoadFrom("C:\\libs\\test.dll");
            Assembly.LoadFrom("/home/user/libs/test.dll");
            Assembly.LoadFrom(@"\\server\share\test.dll");
        }

        // GOOD: path anchored to the application directory.
        public void Good3()
        {
            Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "test.dll"));
        }

        // GOOD: loading by assembly identity rather than by file name.
        public void Good4()
        {
            Assembly.Load("System.Text.Json");
            Assembly.Load("MyPlugin, Version=1.0.0.0, Culture=neutral, PublicKeyToken=0123456789abcdef");
        }
    }
}
