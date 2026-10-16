// Reduced from an ASP.NET WebForms download page that maps the `filename` query
// parameter into a virtual directory and streams the resulting file back.
using System.IO;
using System.Web;
using System.Web.UI;

namespace WebGoat
{
    public class PathManipulation : Page
    {
        public void Page_Load()
        {
            string filename = Request.QueryString["filename"]; // $ Source[cs/path-injection-extended]
            if (filename != null)
            {
                ResponseFile(Request, Response, filename, MapPath("~/Downloads/" + filename));
                ResponseFile(Request, Response, filename, Server.MapPath("~/Downloads/" + filename));
                // Safe: constant file name.
                ResponseFile(Request, Response, "readme.txt", MapPath("~/Downloads/readme.txt"));
            }
        }

        public static void ResponseFile(HttpRequest request, HttpResponse response, string fileName, string fullPath)
        {
            FileStream myFile = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite); // $ Alert[cs/path-injection-extended]
            myFile.Close();
        }
    }
}
