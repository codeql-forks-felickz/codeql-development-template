// Reduced from the Juliet CWE-23 / CWE-36 "01" (baseline) flow variants and the CWE-36
// "81" variant: request data is null-checked and then used (alone, or appended to an
// upload root) to read a file.
using System.IO;
using System.Web;

namespace Juliet
{
    public class RelativePathTraversalParamsGet01
    {
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            string data = req.Params.Get("name"); // $ Source[cs/path-injection-extended]
            string root = "/home/user/uploads/";
            if (data != null)
            {
                if (File.Exists(root + data)) // $ Alert[cs/path-injection-extended]
                {
                    using (StreamReader sr = new StreamReader(root + data)) // $ Alert[cs/path-injection-extended]
                    {
                        sr.ReadLine();
                    }
                }
            }
        }

        public void GoodG2B(HttpRequest req, HttpResponse resp)
        {
            string data = "foo";
            string root = "/home/user/uploads/";
            if (data != null)
            {
                if (File.Exists(root + data))
                {
                    using (StreamReader sr = new StreamReader(root + data))
                    {
                        sr.ReadLine();
                    }
                }
            }
        }
    }

    public class RelativePathTraversalQueryString01
    {
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            string data = "";
            if (req.QueryString["id"] != null)
            {
                data = req.QueryString["id"]; // $ Source[cs/path-injection-extended]
            }
            string root = "/home/user/uploads/";
            if (data != null)
            {
                if (File.Exists(root + data)) // $ Alert[cs/path-injection-extended]
                {
                    using (StreamReader sr = new StreamReader(root + data)) // $ Alert[cs/path-injection-extended]
                    {
                        sr.ReadLine();
                    }
                }
            }
        }
    }

    public class AbsolutePathTraversalParamsGet01
    {
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            string data = req.Params.Get("name"); // $ Source[cs/path-injection-extended]
            if (data != null)
            {
                if (File.Exists(data)) // $ Alert[cs/path-injection-extended]
                {
                    using (StreamReader sr = new StreamReader(data)) // $ Alert[cs/path-injection-extended]
                    {
                        sr.ReadLine();
                    }
                }
            }
        }

        public void GoodG2B(HttpRequest req, HttpResponse resp)
        {
            string data = "foo";
            if (data != null)
            {
                if (File.Exists(data))
                {
                    using (StreamReader sr = new StreamReader(data))
                    {
                        sr.ReadLine();
                    }
                }
            }
        }
    }

    public abstract class AbsolutePathTraversal81Base
    {
        public abstract void Action(string data, HttpRequest req, HttpResponse resp);
    }

    public class AbsolutePathTraversal81Bad : AbsolutePathTraversal81Base
    {
        public override void Action(string data, HttpRequest req, HttpResponse resp)
        {
            if (data != null)
            {
                if (File.Exists(data)) // $ Alert[cs/path-injection-extended]
                {
                    using (StreamReader sr = new StreamReader(data)) // $ Alert[cs/path-injection-extended]
                    {
                        sr.ReadLine();
                    }
                }
            }
        }
    }

    public class AbsolutePathTraversal81QueryString
    {
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            string data = "";
            if (req.QueryString["id"] != null)
            {
                data = req.QueryString["id"]; // $ Source[cs/path-injection-extended]
            }
            AbsolutePathTraversal81Base baseObject = new AbsolutePathTraversal81Bad();
            baseObject.Action(data, req, resp);
        }
    }
}
