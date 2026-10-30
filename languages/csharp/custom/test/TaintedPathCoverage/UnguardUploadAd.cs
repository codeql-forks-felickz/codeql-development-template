// Reduced from unguard "src/ad-service/Pages/ads/upload.cshtml.cs": a Razor Page reads the
// uploaded file from Request.Form.Files and combines its client-supplied name with the web root.
using System.IO;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AdService.Pages
{
    public class UploadAd : PageModel
    {
        private readonly IWebHostEnvironment _appEnvironment;

        public UploadAd(IWebHostEnvironment appEnvironment)
        {
            _appEnvironment = appEnvironment;
        }

        // Stock cs/path-injection misses this: the `Request.Form.Files.Count != 1` check is
        // treated as validating the `Request.Form` source.
        public IActionResult OnPost()
        {
            if (Request.Form.Files.Count != 1 || !Request.Form.Files[0].FileName.EndsWith(".zip"))
            {
                return new OkResult();
            }

            var file = Request.Form.Files[0]; // $ Source[cs/path-injection-extended]
            UploadFile(file);
            UploadFileSafe(file);
            return new OkResult();
        }

        private void UploadFile(IFormFile file)
        {
            var filePath = Path.Combine(_appEnvironment.WebRootPath, "ads", file.FileName);

            if (System.IO.File.Exists(filePath)) // $ Alert[cs/path-injection-extended]
            {
                System.IO.File.Delete(filePath); // $ Alert[cs/path-injection-extended]
            }

            using (var stream = new FileStream(filePath, FileMode.Create)) // $ Alert[cs/path-injection-extended]
            {
                file.CopyTo(stream);
            }
        }

        private void UploadFileSafe(IFormFile file)
        {
            var filePath = Path.Combine(_appEnvironment.WebRootPath, "ads", Path.GetRandomFileName());
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                file.CopyTo(stream);
            }
        }
    }
}
