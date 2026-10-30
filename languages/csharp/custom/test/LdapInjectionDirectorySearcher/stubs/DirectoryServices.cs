// Minimal stubs modelled on System.DirectoryServices public API signatures.
namespace System.DirectoryServices
{
    public class DirectoryEntry
    {
        public DirectoryEntry(string path) => throw null;
    }

    public class SearchResult { }

    public sealed class DirectorySearcher
    {
        public DirectorySearcher(DirectoryEntry searchRoot) => throw null;
        public DirectorySearcher(DirectoryEntry searchRoot, string filter) => throw null;
        public string Filter { get; set; }
        public SearchResult FindOne() => throw null;
    }
}
