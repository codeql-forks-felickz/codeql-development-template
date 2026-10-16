// Minimal stubs of the WCF (System.ServiceModel) and code access security APIs used by the tests.
using System;
using System.Security.Principal;

namespace System.ServiceModel
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Interface, Inherited = false)]
    public sealed class ServiceContractAttribute : Attribute
    {
        public string Namespace { get; set; }
    }

    [AttributeUsage(AttributeTargets.Method)]
    public sealed class OperationContractAttribute : Attribute { }

    public sealed class ServiceSecurityContext
    {
        public static ServiceSecurityContext Current => null;
        public IIdentity PrimaryIdentity => null;
    }
}

namespace System.ServiceModel.Web
{
    [AttributeUsage(AttributeTargets.Method)]
    public sealed class WebInvokeAttribute : Attribute
    {
        public string Method { get; set; }
    }

    [AttributeUsage(AttributeTargets.Method)]
    public sealed class WebGetAttribute : Attribute { }
}

namespace System.Security.Permissions
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = false)]
    public sealed class PrincipalPermissionAttribute : Attribute
    {
        public PrincipalPermissionAttribute(SecurityAction action) { }
        public string Role { get; set; }
    }
}
