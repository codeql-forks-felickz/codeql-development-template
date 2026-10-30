// Minimal stubs modelled on Microsoft.AspNetCore.Mvc public API signatures.
using System;

namespace Microsoft.AspNetCore.Mvc
{
    public abstract class ControllerBase { }

    [AttributeUsage(AttributeTargets.Class)]
    public class ApiControllerAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class RouteAttribute : Attribute
    {
        public RouteAttribute(string template) { }
    }

    [AttributeUsage(AttributeTargets.Method)]
    public class HttpGetAttribute : Attribute
    {
        public HttpGetAttribute(string template) { }
    }
}
