// Minimal stubs for System.Web (not part of .NET Core).
using System.Collections.Specialized;

namespace System.Web
{
    public class HttpRequest
    {
        public NameValueCollection QueryString => null;
        public NameValueCollection Params => null;
    }

    public class HttpResponse { }
}
