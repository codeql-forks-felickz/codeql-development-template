using System;
using System.IO;
using System.Threading.Tasks;
using System.Web.UI;
using System.Web.UI.WebControls;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace WebApp
{
    // CWE-434: Unrestricted upload of file with dangerous type (ASP.NET Web Forms).
    public class CustomerSettings : Page
    {
        protected FileUpload FileUpload1;

        protected void btnUpload_Click(object sender, EventArgs e)
        {
            if (FileUpload1.HasFile)
            {
                string filename = Path.GetFileName(FileUpload1.FileName); // $ Source
                FileUpload1.SaveAs(Server.MapPath("~/WebGoatCoins/uploads/") + filename); // $ Alert
            }
        }

        protected void btnUploadPosted_Click(object sender, EventArgs e)
        {
            string filename = FileUpload1.PostedFile.FileName; // $ Source
            FileUpload1.PostedFile.SaveAs(Path.Combine(Server.MapPath("~/uploads"), filename)); // $ Alert
        }

        protected void btnUploadAllowList_Click(object sender, EventArgs e)
        {
            string filename = Path.GetFileName(FileUpload1.FileName);
            string ext = Path.GetExtension(filename).ToLowerInvariant();
            if (ext == ".png" || ext == ".jpg")
            {
                FileUpload1.SaveAs(Server.MapPath("~/uploads/") + filename);
            }
        }

        protected void btnUploadRenamed_Click(object sender, EventArgs e)
        {
            string filename = Guid.NewGuid().ToString() + ".png";
            FileUpload1.SaveAs(Server.MapPath("~/uploads/") + filename);
        }

        protected void btnUploadChangeExtension_Click(object sender, EventArgs e)
        {
            string filename = Path.ChangeExtension(Path.GetFileName(FileUpload1.FileName), ".bin");
            FileUpload1.SaveAs(Server.MapPath("~/uploads/") + filename);
        }

        protected void btnUploadOutsideWebRoot_Click(object sender, EventArgs e)
        {
            string filename = Path.GetFileName(FileUpload1.FileName);
            FileUpload1.SaveAs(Path.Combine("/var/app-data/uploads", filename));
        }
    }

    // CWE-434: Unrestricted upload of file with dangerous type (ASP.NET Core).
    public class UploadController : Controller
    {
        private readonly IWebHostEnvironment env;

        public UploadController(IWebHostEnvironment env) { this.env = env; }

        [HttpPost]
        public async Task Upload(IFormFile file)
        {
            var path = Path.Combine(env.WebRootPath, "uploads", file.FileName); // $ Source
            using (var stream = new FileStream(path, FileMode.Create)) // $ Alert
            {
                await file.CopyToAsync(stream);
            }
        }

        [HttpPost]
        public void UploadAllowList(IFormFile file)
        {
            var ext = Path.GetExtension(file.FileName);
            if (ext != ".png")
                return;
            var path = Path.Combine(env.WebRootPath, "uploads", file.FileName);
            using (var stream = File.Create(path))
            {
                file.CopyTo(stream);
            }
        }

        [HttpPost]
        public void UploadRandomName(IFormFile file)
        {
            var path = Path.Combine(env.WebRootPath, "uploads", Path.GetRandomFileName());
            using (var stream = File.Create(path))
            {
                file.CopyTo(stream);
            }
        }
    }
}
