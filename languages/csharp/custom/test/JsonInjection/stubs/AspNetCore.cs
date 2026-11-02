// Minimal stubs for the ASP.NET Core types used by this test.
namespace Microsoft.AspNetCore.Http
{
    public interface IRequestCookieCollection
    {
        string this[string key] { get; }
    }

    public abstract class HttpRequest
    {
        public abstract IRequestCookieCollection Cookies { get; }
    }
}

namespace Microsoft.AspNetCore.Mvc.RazorPages
{
    public abstract class PageModel
    {
        public Microsoft.AspNetCore.Http.HttpRequest Request => null;
    }
}
