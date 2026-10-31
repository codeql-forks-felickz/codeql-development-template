using System;

namespace System.Web.Http
{
    public class AuthorizeAttribute : Attribute { }
    public class HttpPostAttribute : Attribute { }
    public class ApiController { }

    public class HttpConfiguration
    {
        public Filters.HttpFilterCollection Filters { get; } = new Filters.HttpFilterCollection();
    }
}

namespace System.Web.Http.Filters
{
    public class HttpFilterCollection
    {
        public void Add(object filter) { }
    }
}
