// Reduced from an ASP.NET WebForms page that appends the `content` query parameter
// to a static directory, copies it character by character and opens it.
using System.IO;
using System.Web.UI;

namespace Altoro
{
    public class DefaultPage : Page
    {
        private string LoadFile(string myFile)
        {
            string returnString = "";
            string fileType = myFile.Substring(myFile.Length - 4, 4);
            if (fileType == ".txt" || fileType == ".htm")
            {
                string openFile = "";
                int i = 0;
                while (myFile[i] != 0)
                {
                    openFile += myFile[i];
                    i++;
                    if (i == myFile.Length)
                        break;
                }

                TextReader infile = File.OpenText(openFile); // $ Alert[cs/path-injection-extended]
                returnString = infile.ReadLine();
                infile.Close();
            }
            return returnString;
        }

        private string LoadFileDirect(string myFile)
        {
            TextReader infile = File.OpenText(myFile); // $ Alert[cs/path-injection-extended]
            string result = infile.ReadLine();
            infile.Close();
            return result;
        }

        public void Page_Load()
        {
            string fileToLoad = Server.MapPath("") + "./static/";
            if (Request.QueryString["content"] == null)
            {
                fileToLoad += "default.htm";
            }
            else
            {
                fileToLoad += Request.QueryString["content"]; // $ Source[cs/path-injection-extended]
            }
            LoadFile(fileToLoad);
            LoadFileDirect(fileToLoad);
        }

        public void Page_Load_Safe()
        {
            string fileToLoad = Server.MapPath("") + "./static/default.htm";
            LoadFile(fileToLoad);
        }
    }
}
