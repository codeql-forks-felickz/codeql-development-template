// Minimal stubs for the System.DirectoryServices types used by this test.
namespace System.DirectoryServices
{
    public class DirectoryEntry
    {
        public DirectoryEntry(string path) { }
    }

    public class SearchResult { }

    public class DirectorySearcher
    {
        public DirectorySearcher(DirectoryEntry searchRoot) { }
        public string Filter { get; set; }
        public SearchResult FindOne() => null;
    }
}
