// Null, length and single-character checks do not validate a path, but real checks do.
using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace Guards
{
    [ApiController]
    [Route("[controller]")]
    public class GuardsController : ControllerBase
    {
        public string NotNull(string name) // $ Source[cs/path-injection-extended]
        {
            if (name != null)
                return File.ReadAllText(name); // $ Alert[cs/path-injection-extended]
            return "";
        }

        public string IsNotNull(string name) // $ Source[cs/path-injection-extended]
        {
            if (name is not null)
                return File.ReadAllText(name); // $ Alert[cs/path-injection-extended]
            return "";
        }

        public string NotNullAndNotEmpty(string name) // $ Source[cs/path-injection-extended]
        {
            if (name != null && name.Length > 0 && name[0] != '/')
                return File.ReadAllText(name); // $ Alert[cs/path-injection-extended]
            return "";
        }

        public string NoGuard(string name) // $ Source[cs/path-injection] Source[cs/path-injection-extended]
        {
            return File.ReadAllText(name); // $ Alert[cs/path-injection] Alert[cs/path-injection-extended]
        }

        public string Validated(string name)
        {
            if (name != null && !name.Contains(".."))
                return File.ReadAllText(name);
            return "";
        }

        public string Allowlisted(string name)
        {
            if (IsAllowed(name))
                return File.ReadAllText(name);
            return "";
        }

        private static bool IsAllowed(string name) => name == "a.txt" || name == "b.txt";
    }
}
