// Reduced from an ASP.NET Core API controller that saves an uploaded file using the
// client-supplied multipart file name.
using System.IO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Uploads
{
    [ApiController]
    [Route("[controller]")]
    public class UploadController : ControllerBase
    {
        [HttpPost(Name = "UploadFile")]
        public void SaveFile(IFormFile file) // $ Source[cs/path-injection] Source[cs/path-injection-extended]
        {
            string filePath = Path.Combine(@"C:\temp", file.FileName);
            using var stream = new FileStream(filePath, FileMode.Create); // $ Alert[cs/path-injection] Alert[cs/path-injection-extended]
            file.CopyTo(stream);
        }

        [HttpPost(Name = "UploadFileSafe")]
        public void SaveFileSafe(IFormFile file)
        {
            string filePath = Path.Combine(@"C:\temp", Path.GetRandomFileName());
            using var stream = new FileStream(filePath, FileMode.Create);
            file.CopyTo(stream);
        }
    }
}
