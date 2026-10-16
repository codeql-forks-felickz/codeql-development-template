// Minimal System.Web stubs so the test database can be extracted without .NET Framework.
using System.Collections.Specialized;

namespace System.Web
{
    public class HttpRequest
    {
        public NameValueCollection QueryString => null;
    }

    public class HttpResponse { }
}
