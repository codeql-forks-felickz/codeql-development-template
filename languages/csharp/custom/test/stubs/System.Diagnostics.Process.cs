// Minimal stubs for `System.Diagnostics.Process`, which is not referenced by the C# qltest extractor.
// Stubs live outside each test directory so that they are extracted as library (non-source) code.

namespace System.Diagnostics
{
    public sealed class ProcessStartInfo
    {
        public ProcessStartInfo() => throw null;
        public ProcessStartInfo(string fileName) => throw null;
        public ProcessStartInfo(string fileName, string arguments) => throw null;
        public string Arguments { get => throw null; set => throw null; }
        public System.Collections.ObjectModel.Collection<string> ArgumentList { get => throw null; }
        public string FileName { get => throw null; set => throw null; }
        public bool UseShellExecute { get => throw null; set => throw null; }
        public string WorkingDirectory { get => throw null; set => throw null; }
    }

    public class Process : System.IDisposable
    {
        public Process() => throw null;
        public ProcessStartInfo StartInfo { get => throw null; set => throw null; }
        public bool Start() => throw null;
        public static Process Start(ProcessStartInfo startInfo) => throw null;
        public static Process Start(string fileName) => throw null;
        public static Process Start(string fileName, string arguments) => throw null;
        public static Process Start(string fileName, System.Collections.Generic.IEnumerable<string> arguments) => throw null;
        public void Dispose() => throw null;
    }
}
