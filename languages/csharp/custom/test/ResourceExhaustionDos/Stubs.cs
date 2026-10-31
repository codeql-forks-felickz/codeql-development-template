// Minimal stubs for System.Web (ASP.NET on .NET Framework), which is not
// available in the .NET runtime used to extract this test.
namespace System.Web
{
    public class HttpRequest
    {
        public System.Collections.Specialized.NameValueCollection Params => null;
        public System.Collections.Specialized.NameValueCollection QueryString => null;
    }

    public class HttpResponse { }
}

namespace System.Web.UI
{
    public class Control { }

    public class Page : Control { }
}

namespace System.Web.UI.WebControls
{
    public class TextBox : System.Web.UI.Control
    {
        public virtual string Text { get; set; }
    }

    public class Label : System.Web.UI.Control
    {
        public virtual string Text { get; set; }
    }
}
