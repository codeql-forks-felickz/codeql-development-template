using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JsonInjectionTest
{
    public class Session
    {
        public string Role { get; set; }
    }

    public static class AuthClient
    {
        private static readonly HttpClient httpClient = new HttpClient();

        public static async Task<bool> IsTokenValid(string jwt)
        {
            var payload = "{\"jwt\":\"" + jwt + "\"}"; // $ Alert
            var content = new StringContent(payload, Encoding.UTF8, "application/json");
            var response = await httpClient.PostAsync("http://auth/isValid", content);
            return response.IsSuccessStatusCode;
        }

        public static string BuildLoginBody(string user)
        {
            return string.Format("{{\"user\":\"{0}\",\"role\":\"viewer\"}}", user); // $ Alert
        }
    }

    public class DeleteModel : PageModel
    {
        private static readonly HttpClient httpClient = new HttpClient();

        public async Task OnPostAsync(string fileName, int count) // $ Source
        {
            var jwt = Request.Cookies["jwt"]; // $ Source
            await AuthClient.IsTokenValid(jwt);

            // Interpolated JSON text that is parsed.
            var doc = JsonDocument.Parse($"{{\"user\":\"{jwt}\"}}"); // $ Alert

            // JSON text built with `+=`.
            var body = "{";
            body += "\"file\":\"" + fileName + "\""; // $ Alert
            body += "}";
            var node = JsonNode.Parse(body);

            // JSON text built in another method and sent with a media type constant.
            var login = AuthClient.BuildLoginBody(jwt);
            await httpClient.PostAsync("http://auth/login",
                new StringContent(login, Encoding.UTF8, MediaTypeNames.Application.Json));

            // Media type given as a `MediaTypeHeaderValue`.
            await httpClient.PostAsync("http://auth/check",
                new StringContent("{\"token\":\"" + jwt + "\"}", Encoding.UTF8, new MediaTypeHeaderValue("application/json"))); // $ Alert

            // Newtonsoft.Json parsing and deserialization.
            var jobj = JObject.Parse("{\"file\":\"" + fileName + "\"}"); // $ Alert
            var session = JsonConvert.DeserializeObject<Session>("{\"role\":\"user\",\"name\":\"" + jwt + "\"}"); // $ Alert

            // System.Text.Json deserialization.
            var session2 = System.Text.Json.JsonSerializer.Deserialize<Session>("{\"name\":\"" + jwt + "\",\"role\":\"user\"}"); // $ Alert

            // GOOD: constant JSON text.
            await httpClient.PostAsync("http://auth/ping",
                new StringContent("{\"ping\":true}", Encoding.UTF8, "application/json"));

            // GOOD: a numeric value cannot change the JSON structure.
            JsonDocument.Parse("{\"count\":" + count + "}");

            // GOOD: the JSON text is produced by a serializer.
            await httpClient.PostAsync("http://auth/isValid",
                new StringContent(System.Text.Json.JsonSerializer.Serialize(new { jwt }), Encoding.UTF8, "application/json"));

            // GOOD: the value is encoded as a JSON string before it is inserted.
            JsonDocument.Parse("{\"jwt\":" + System.Text.Json.JsonSerializer.Serialize(jwt) + "}");
            JsonDocument.Parse("{\"jwt\":\"" + JavaScriptEncoder.Default.Encode(jwt) + "\"}");
            JsonDocument.Parse("{\"jwt\":" + JsonConvert.SerializeObject(jwt) + "}");

            // GOOD: not JSON text.
            await httpClient.PostAsync("http://auth/form",
                new StringContent("token=" + jwt, Encoding.UTF8, "application/x-www-form-urlencoded"));

            // GOOD: JSON-like text that is only logged, not used as JSON.
            Console.WriteLine("{\"jwt\":\"" + jwt + "\"}");

            // GOOD: JSON-like text sent as plain text.
            await httpClient.PostAsync("http://auth/text",
                new StringContent("{\"jwt\":\"" + jwt + "\"}", Encoding.UTF8, "text/plain"));
        }
    }
}
