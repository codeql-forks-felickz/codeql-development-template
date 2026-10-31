// Reduced from an ASP.NET Core API controller that concatenates a route value
// into an `ILogger<T>` message. The controller name does not end in
// `Controller`, but `[ApiController]`/`ControllerBase` still make its action
// parameters remote flow sources, so the stock `cs/log-forging` query covers
// this pattern when Microsoft.AspNetCore and Microsoft.Extensions.Logging
// resolve.
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace WebFox.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LogInjection : ControllerBase
    {
        private readonly ILogger<LogInjection> _logger;

        public LogInjection(ILogger<LogInjection> logger)
        {
            _logger = logger;
        }

        [HttpGet("{userInfo}")]
        public void injectLog(string userInfo) // $ Source
        {
            _logger.LogError("error!! " + userInfo);
        }

        [HttpGet("{userInfo}")]
        public void injectLogSanitized(string userInfo)
        {
            // Safe: CR/LF removed before logging.
            _logger.LogError("error!! " + userInfo.Replace("\r", "").Replace("\n", ""));
        }

        [HttpGet("{userInfo}")]
        public void injectLogConstant(string userInfo)
        {
            // Safe: constant message.
            _logger.LogInformation("request received");
        }
    }
}
