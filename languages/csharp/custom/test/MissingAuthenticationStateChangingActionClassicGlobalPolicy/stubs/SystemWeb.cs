using System;

namespace System.Web.Mvc
{
    public class AuthorizeAttribute : Attribute { }
    public class HttpPostAttribute : Attribute { }

    public class GlobalFilterCollection
    {
        public void Add(object filter) { }
    }

    public static class GlobalFilters
    {
        public static GlobalFilterCollection Filters { get; } = new GlobalFilterCollection();
    }

    public class Controller { }
}

namespace System.Web.Http
{
    public class AuthorizeAttribute : Attribute { }
    public class HttpPostAttribute : Attribute { }
    public class ApiController { }
}

namespace System.Web.Http.Filters
{
    public class HttpFilterCollection
    {
        public void Add(object filter) { }
    }
}

namespace System.Web.Http
{
    public class HttpConfiguration
    {
        public Filters.HttpFilterCollection Filters { get; } = new Filters.HttpFilterCollection();
    }
}
