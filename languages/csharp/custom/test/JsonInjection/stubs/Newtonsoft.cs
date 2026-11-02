// Minimal stubs for the Newtonsoft.Json types used by this test.
namespace Newtonsoft.Json
{
    public static class JsonConvert
    {
        public static string SerializeObject(object value) => null;
        public static T DeserializeObject<T>(string value) => default(T);
    }
}

namespace Newtonsoft.Json.Linq
{
    public class JToken { }

    public class JObject : JToken
    {
        public static new JObject Parse(string json) => null;
    }
}
