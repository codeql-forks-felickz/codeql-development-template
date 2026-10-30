// Minimal stubs modelled on Microsoft.AspNetCore.Mvc public API signatures.
using System;

namespace Microsoft.AspNetCore.Mvc
{
    public interface IActionResult { }

    public abstract class ControllerBase
    {
        public RedirectToActionResult RedirectToAction(string actionName) => throw null;
    }

    public abstract class Controller : ControllerBase { }

    public class RedirectToActionResult : IActionResult { }

    [AttributeUsage(AttributeTargets.Method)]
    public class HttpPostAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Parameter)]
    public class BindAttribute : Attribute
    {
        public BindAttribute(params string[] include) { }
    }
}
