using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace RequestForgeryTests
{
    // Reduced from an `Import` action that proxies a query-string URL through HttpClient.
    [Route("api/[controller]")]
    public class UsersController : Controller
    {
        private static readonly HttpClient client = new HttpClient();

        [HttpGet("import")]
        public async Task<IActionResult> Import()
        {
            var url = HttpContext.Request.Query["url"].ToString(); // $ Source
            HttpResponseMessage response = await client.GetAsync(url); // $ Alert
            return Ok(await response.Content.ReadAsStringAsync());
        }

        [HttpGet("uri")]
        public async Task<string> ImportUri(string url) // $ Source
        {
            return await client.GetStringAsync(new Uri(url)); // $ Alert
        }

        [HttpGet("message")]
        public async Task<HttpResponseMessage> ImportMessage(string url) // $ Source
        {
            var request = new HttpRequestMessage(HttpMethod.Get, url); // $ Alert
            return await client.SendAsync(request);
        }

        [HttpGet("scheme")]
        public async Task<string> ImportHost(string host) // $ Source
        {
            // A scheme-only prefix still lets the caller pick the host.
            return await client.GetStringAsync("http://" + host); // $ Alert
        }

        [HttpGet("webrequest")]
        public WebResponse ImportWebRequest(string url) // $ Source
        {
            return WebRequest.Create(url).GetResponse(); // $ Alert
        }

        [HttpGet("baseaddress")]
        public void SetBaseAddress(string url) // $ Source
        {
            var c = new HttpClient();
            c.BaseAddress = new Uri(url); // $ Alert
        }

        // GOOD: the URL is checked against a trusted base URI before use.
        [HttpGet("allowlisted")]
        public async Task<string> ImportAllowListed(string url)
        {
            var trusted = new Uri("https://imports.example.com/");
            var target = new Uri(url);
            if (trusted.IsBaseOf(target))
            {
                return await client.GetStringAsync(target);
            }
            return null;
        }

        // GOOD: the host of the URL is compared against a trusted value before use.
        [HttpGet("hostcheck")]
        public async Task<string> ImportHostChecked(string url)
        {
            var target = new Uri(url);
            if (target.Host == "imports.example.com")
            {
                return await client.GetStringAsync(target);
            }
            return null;
        }

        // GOOD: the URL must start with a trusted scheme and host.
        [HttpGet("prefixcheck")]
        public async Task<string> ImportPrefixChecked(string url)
        {
            if (url.StartsWith("https://imports.example.com/"))
            {
                return await client.GetStringAsync(url);
            }
            return null;
        }

        // BAD: a scheme-only prefix check does not restrict the host.
        [HttpGet("schemecheck")]
        public async Task<string> ImportSchemeChecked(string url) // $ Source
        {
            if (url.StartsWith("https://"))
            {
                return await client.GetStringAsync(url); // $ Alert
            }
            return null;
        }

        // GOOD: user input only selects a path/query on a fixed host.
        [HttpGet("fixedhost")]
        public async Task<string> ImportFixedHost(string id)
        {
            var a = await client.GetStringAsync("https://api.example.com/users?id=" + id);
            var b = await client.GetStringAsync($"https://api.example.com/users/{id}");
            return a + b;
        }

        // GOOD: constant URL.
        [HttpGet("constant")]
        public async Task<string> ImportConstant()
        {
            return await client.GetStringAsync("https://api.example.com/users");
        }
    }

    // Reduced from a `CallWebService` action that downloads a caller-supplied URL with WebClient.
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        [HttpPost(Name = "CallWebService")]
        public void CallWebService(string url) // $ Source
        {
            WebClient client = new WebClient();
            string response = client.DownloadString(url); // $ Alert
        }

        [HttpPost(Name = "CallWebServiceData")]
        public byte[] CallWebServiceData(string url) // $ Source
        {
            using var client = new WebClient();
            return client.DownloadData(new Uri(url)); // $ Alert
        }

        // GOOD: user input is only sent as the request body, not the destination.
        [HttpPost(Name = "Upload")]
        public string Upload(string body)
        {
            using var client = new WebClient();
            return client.UploadString("https://api.example.com/upload", body);
        }
    }
}
