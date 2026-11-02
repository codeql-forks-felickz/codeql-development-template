// Minimal framework stubs for the test database.

namespace System.Web
{
    public class HttpRequest
    {
        public string this[string key] => null;

        public bool IsLocal => false;
    }

    public class TraceContext
    {
        public bool IsEnabled { get; set; }
    }
}

namespace System.Web.UI
{
    public class Control
    {
        public System.Web.HttpRequest Request => null;
    }

    public class TemplateControl : Control { }

    public class Page : TemplateControl
    {
        public System.Web.TraceContext Trace => null;
    }
}

namespace Microsoft.AspNetCore.Builder
{
    public interface IApplicationBuilder { }

    public static class DeveloperExceptionPageExtensions
    {
        public static IApplicationBuilder UseDeveloperExceptionPage(this IApplicationBuilder app) => app;
    }

    public static class DatabaseErrorPageExtensions
    {
        public static IApplicationBuilder UseDatabaseErrorPage(this IApplicationBuilder app) => app;
    }

    public static class ExceptionHandlerExtensions
    {
        public static IApplicationBuilder UseExceptionHandler(this IApplicationBuilder app, string path) => app;
    }
}

namespace Microsoft.AspNetCore.Hosting
{
    public interface IWebHostEnvironment
    {
        string EnvironmentName { get; }
    }

    public static class HostingEnvironmentExtensions
    {
        public static bool IsDevelopment(this IWebHostEnvironment env) => false;

        public static bool IsEnvironment(this IWebHostEnvironment env, string name) => false;

        public static bool IsProduction(this IWebHostEnvironment env) => false;

        public static bool IsStaging(this IWebHostEnvironment env) => false;
    }
}
