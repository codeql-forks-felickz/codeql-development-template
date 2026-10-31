// Minimal stubs for the ASP.NET Web Forms (System.Web) APIs used by the tests.
namespace System.Collections.Specialized
{
    public class NameValueCollection
    {
        public string this[string name] { get => null; set { } }
    }
}

namespace System.Web
{
    public class HttpRequest
    {
        public System.Collections.Specialized.NameValueCollection QueryString => null;
    }

    public class HttpResponse
    {
        public void Redirect(string url) { }
        public void Redirect(string url, bool endResponse) { }
    }
}

namespace System.Web.UI
{
    public class Control
    {
        public virtual Control FindControl(string id) => null;
    }

    public class Page : Control
    {
        public System.Web.HttpRequest Request => null;
        public System.Web.HttpResponse Response => null;
        public bool IsPostBack => false;
    }
}

namespace System.Web.UI.WebControls
{
    public class TextBox : System.Web.UI.Control
    {
        public virtual string Text { get; set; }
    }

    public class Wizard : System.Web.UI.Control
    {
        public virtual string FinishDestinationPageUrl { get; set; }
        public virtual string CancelDestinationPageUrl { get; set; }
    }

    public class CreateUserWizard : Wizard
    {
        public virtual string ContinueDestinationPageUrl { get; set; }
        public virtual string UserName { get; set; }
    }
}

// Minimal stubs for the ASP.NET Core MVC APIs used by the tests.
namespace Microsoft.AspNetCore.Mvc
{
    public interface IActionResult { }

    public class RedirectResult : IActionResult { }

    public abstract class ControllerBase
    {
        public virtual RedirectResult Redirect(string url) => null;
    }

    public abstract class Controller : ControllerBase { }
}
