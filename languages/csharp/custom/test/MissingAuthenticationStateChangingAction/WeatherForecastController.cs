// Sanitized reproduction: API controller exposing dangerous POST endpoints, with no authorization configured.
using System.Diagnostics;
using System.IO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Xss.Server.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        // GOOD: read-only.
        [HttpGet(Name = "GetWeatherForecast")]
        public string[] Get() => new[] { "Mild" };

        // BAD: unauthenticated file write.
        [HttpPost(Name = "UploadFile")]
        public void SaveFile(IFormFile file) // $ Alert[cs/web/missing-authentication-state-changing-action]
        {
            using var stream = new FileStream(Path.Combine("/tmp", file.FileName), FileMode.Create);
            file.CopyTo(stream);
        }

        // BAD: unauthenticated command execution.
        [HttpPost(Name = "ExecuteCommand")]
        public void ExecuteCommand(string command) // $ Alert[cs/web/missing-authentication-state-changing-action]
        {
            Process.Start("sh", "-c " + command);
        }

        // GOOD: checks the caller in code.
        [HttpPost(Name = "Purge")]
        public IActionResult Purge(int id)
        {
            if (!User.Identity.IsAuthenticated)
                return Unauthorized();
            return Ok(id);
        }

        // GOOD: empty action.
        [HttpPost(Name = "Ping")]
        public void Ping() { }
    }
}
