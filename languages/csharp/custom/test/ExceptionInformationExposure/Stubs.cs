// Minimal framework stubs for the test database.

namespace System.Web
{
    public class HttpRequest
    {
        public string this[string key] => null;
    }

    public class HttpResponse
    {
        public void Write(string s) { }
    }

    public class HttpContext
    {
        public HttpRequest Request => null;
        public HttpResponse Response => null;
    }

    public interface IHttpHandler
    {
        void ProcessRequest(HttpContext context);
    }
}

namespace System.Web.UI
{
    public class Control
    {
        public System.Web.HttpRequest Request => null;
        public System.Web.HttpResponse Response => null;
    }

    public class TemplateControl : Control { }

    public class Page : TemplateControl { }
}

namespace System.Web.UI.WebControls
{
    public class Label : System.Web.UI.Control
    {
        public string Text { get; set; }
    }
}

namespace System.Web.Services
{
    public class WebService { }

    public class WebMethodAttribute : System.Attribute { }
}

namespace Microsoft.AspNetCore.Http
{
    public interface IFeatureCollection
    {
        T Get<T>();
    }

    public class HttpContext
    {
        public IFeatureCollection Features => null;
    }
}

namespace Microsoft.AspNetCore.Diagnostics
{
    public interface IExceptionHandlerFeature
    {
        System.Exception Error { get; }
    }

    public interface IExceptionHandlerPathFeature : IExceptionHandlerFeature
    {
        string Path { get; }
    }
}

namespace Microsoft.AspNetCore.Mvc
{
    public interface IActionResult { }

    public class ObjectResult : IActionResult
    {
        public ObjectResult(object value) { }
    }

    public class ContentResult : IActionResult
    {
        public string Content { get; set; }
    }

    public class ApiControllerAttribute : System.Attribute { }

    public abstract class ControllerBase
    {
        public Microsoft.AspNetCore.Http.HttpContext HttpContext => null;

        public virtual ObjectResult Ok(object value) => null;

        public virtual ObjectResult StatusCode(int statusCode, object value) => null;

        public virtual IActionResult StatusCode(int statusCode) => null;

        public virtual ObjectResult BadRequest(object error) => null;

        public virtual ContentResult Content(string content) => null;
    }

    public abstract class Controller : ControllerBase
    {
        public virtual IActionResult View(object model) => null;

        public virtual IActionResult Json(object data) => null;
    }
}

namespace Microsoft.AspNetCore.Mvc.Razor
{
    public abstract class RazorPageBase
    {
        public virtual void Write(object value) { }

        public virtual void WriteLiteral(object value) { }
    }

    public abstract class RazorPage<TModel> : RazorPageBase
    {
        public TModel Model => default(TModel);
    }
}

namespace Newtonsoft.Json.Linq
{
    public class JToken { }

    public class JProperty : JToken
    {
        public JProperty(string name, object content) { }
    }

    public class JObject : JToken
    {
        public JObject(params object[] content) { }
    }
}

namespace System.Web.Mvc
{
    public abstract class Controller { }
}

namespace System.Web.Http
{
    public abstract class ApiController { }
}
