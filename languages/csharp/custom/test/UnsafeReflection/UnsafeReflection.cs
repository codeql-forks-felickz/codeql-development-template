using System;
using System.Collections.Generic;
using System.Reflection;
using System.Web;
using Microsoft.AspNetCore.Mvc;

namespace UnsafeReflectionTests
{
    // Reduced from a Juliet CWE-470 test case: a query-string value names the type to instantiate.
    public class QueryStringReflection
    {
        public void Bad(HttpRequest req)
        {
            string data = "";
            if (req.QueryString["id"] != null)
            {
                data = req.QueryString["id"]; // $ Source
            }
            var container = Activator.CreateInstance(null, data); // $ Alert
            object obj = container.Unwrap();
        }

        // Juliet CWE-470 `Web_Params_Get_Web` variant: the type name comes from `Params.Get`.
        public void BadParamsGet(HttpRequest req)
        {
            string data = req.Params.Get("name"); // $ Source
            var container = Activator.CreateInstance(null, data); // $ Alert
            object obj = container.Unwrap();
        }

        // Juliet CWE-470 flow variant 73: the type name is passed through a LinkedList.
        public void BadLinkedList(HttpRequest req)
        {
            string data = req.QueryString["id"]; // $ Source
            LinkedList<string> dataLinkedList = new LinkedList<string>();
            dataLinkedList.AddLast(data);
            BadLinkedListSink(dataLinkedList);
        }

        private static void BadLinkedListSink(LinkedList<string> dataLinkedList)
        {
            string data = dataLinkedList.Last.Value;
            var container = Activator.CreateInstance(null, data); // $ Alert
            object obj = container.Unwrap();
        }

        // GOOD: the LinkedList only holds a hardcoded type name.
        public void GoodLinkedList()
        {
            LinkedList<string> dataLinkedList = new LinkedList<string>();
            dataLinkedList.AddLast("Testing.test");
            var container = Activator.CreateInstance(null, dataLinkedList.First.Value);
            object obj = container.Unwrap();
        }

        // GOOD: hardcoded type name.
        public void GoodG2B(HttpRequest req)
        {
            string data = "Testing.test";
            var container = Activator.CreateInstance(null, data);
            object obj = container.Unwrap();
        }
    }

    [ApiController]
    [Route("[controller]")]
    public class PluginController : ControllerBase
    {
        private static readonly HashSet<string> AllowedTypes = new HashSet<string> { "Plugins.Safe" };
        private static readonly Dictionary<string, bool> AllowedTypeMap =
            new Dictionary<string, bool> { { "Plugins.Safe", true } };

        [HttpPost("type")]
        public object CreateFromType(string typeName) // $ Source
        {
            Type t = Type.GetType(typeName);
            return Activator.CreateInstance(t); // $ Alert
        }

        [HttpPost("assembly")]
        public object CreateFromAssembly(string typeName) // $ Source
        {
            return Assembly.GetExecutingAssembly().CreateInstance(typeName); // $ Alert
        }

        [HttpPost("file")]
        public object CreateFromFile(string assemblyFile) // $ Source
        {
            return Activator.CreateInstanceFrom(assemblyFile, "Plugins.Safe"); // $ Alert
        }

        [HttpPost("invoke")]
        public object Invoke(string typeName) // $ Source
        {
            Type t = Assembly.GetExecutingAssembly().GetType(typeName);
            return t.InvokeMember("Run", BindingFlags.InvokeMethod, null, null, null); // $ Alert
        }

        // GOOD: the type name is checked against an allowlist.
        [HttpPost("allowlisted")]
        public object CreateAllowListed(string typeName)
        {
            if (AllowedTypes.Contains(typeName))
            {
                return Activator.CreateInstance(Type.GetType(typeName));
            }
            return null;
        }

        [HttpPost("tainted-allowlist")]
        public object CreateFromTaintedAllowList(string typeName) // $ Source
        {
            var allowedTypes = new List<string>();
            allowedTypes.Add(typeName);
            if (allowedTypes.Contains(typeName))
            {
                return Activator.CreateInstance(Type.GetType(typeName)); // $ Alert
            }
            return null;
        }

        [HttpPost("tainted-allowlist-key")]
        public object CreateFromTaintedAllowListKey(string typeName) // $ Source
        {
            if (HttpContext.Request.Query.ContainsKey(typeName))
            {
                return Activator.CreateInstance(Type.GetType(typeName)); // $ Alert
            }
            return null;
        }

        [HttpPost("allowlisted-key")]
        public object CreateFromAllowListedKey(string typeName)
        {
            if (AllowedTypeMap.ContainsKey(typeName))
            {
                return Activator.CreateInstance(Type.GetType(typeName));
            }
            return null;
        }

        // GOOD: the type name is compared against a constant.
        [HttpPost("constant")]
        public object CreateConstantChecked(string typeName)
        {
            if (typeName == "Plugins.Safe")
            {
                return Activator.CreateInstance(Type.GetType(typeName));
            }
            return null;
        }

        // GOOD: resolving a type without instantiating or invoking it.
        [HttpPost("lookup")]
        public string Lookup(string typeName)
        {
            return Type.GetType(typeName)?.FullName;
        }
    }
}
