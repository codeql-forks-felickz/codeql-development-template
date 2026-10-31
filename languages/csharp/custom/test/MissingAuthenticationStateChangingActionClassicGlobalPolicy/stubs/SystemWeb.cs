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
