// Reduced from an ASP.NET WebForms page that maps the `image` request parameter to a
// physical path and sends the file with `HttpResponse.TransmitFile`.
using System.IO;
using System.Web.UI;

namespace WebGoat
{
    public class Orders : Page
    {
        public void Page_Load()
        {
            string target_image = Request["image"]; // $ Source[cs/path-injection-extended]
            if (target_image != null)
            {
                FileInfo fi = new FileInfo(Server.MapPath(target_image));
                Response.ContentType = "image/png";
                Response.AppendHeader("Content-Disposition", "attachment; filename=" + fi.Name);
                Response.TransmitFile(fi.FullName); // $ Alert[cs/path-injection-extended]
                Response.End();
            }
        }

        public void Page_Load_Unguarded()
        {
            string target_image = Request["image"]; // $ Source[cs/path-injection-extended]
            Response.WriteFile(Server.MapPath(target_image)); // $ Alert[cs/path-injection-extended]
        }

        public void Page_Load_Safe()
        {
            Response.TransmitFile(Server.MapPath("~/images/products/logo.png"));
        }
    }
}
