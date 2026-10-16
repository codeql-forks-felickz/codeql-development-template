// Reduced from the Juliet CWE-23 "81" flow variant: request data is passed to an
// abstract method whose concrete override concatenates it with an upload root and
// reads the file.
using System.IO;
using System.Web;

namespace Juliet
{
    public abstract class RelativePathTraversal81Base
    {
        public abstract void Action(string data, HttpRequest req, HttpResponse resp);
    }

    public class RelativePathTraversal81Bad : RelativePathTraversal81Base
    {
        public override void Action(string data, HttpRequest req, HttpResponse resp)
        {
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

    public class RelativePathTraversal81Good : RelativePathTraversal81Base
    {
        public override void Action(string data, HttpRequest req, HttpResponse resp)
        {
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

    public class RelativePathTraversal81QueryString
    {
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            string data = "";
            if (req.QueryString["id"] != null)
            {
                data = req.QueryString["id"]; // $ Source[cs/path-injection-extended]
            }
            RelativePathTraversal81Base baseObject = new RelativePathTraversal81Bad();
            baseObject.Action(data, req, resp);
        }

        public void Good(HttpRequest req, HttpResponse resp)
        {
            string data = "foo";
            RelativePathTraversal81Base baseObject = new RelativePathTraversal81Good();
            baseObject.Action(data, req, resp);
        }
    }

    public class RelativePathTraversal81ParamsGet
    {
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            string data = req.Params.Get("name"); // $ Source[cs/path-injection-extended]
            RelativePathTraversal81Base baseObject = new RelativePathTraversal81Bad();
            baseObject.Action(data, req, resp);
        }
    }
}
