// Minimal stubs for the parts of System.Web used by the tests.
namespace System.Web.UI
{
    public class Control { }

    public class TemplateControl : Control { }

    public class Page : TemplateControl { }
}

namespace System.Web.UI.WebControls
{
    public class WebControl : System.Web.UI.Control { }

    public class TextBox : WebControl
    {
        public virtual string Text { get; set; }
    }

    public class Label : WebControl
    {
        public virtual string Text { get; set; }
    }
}
