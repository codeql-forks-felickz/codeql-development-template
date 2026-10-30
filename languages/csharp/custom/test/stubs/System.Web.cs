// Minimal stubs for ASP.NET Web Forms.

namespace System.Web.UI
{
    public class Control { }

    public class Page : Control { }
}

namespace System.Web.UI.WebControls
{
    public class WebControl : System.Web.UI.Control { }

    public class TextBox : WebControl
    {
        public virtual string Text { get => throw null; set => throw null; }
    }
}
