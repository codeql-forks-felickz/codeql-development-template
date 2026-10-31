namespace System.Web
{
    public class HttpRequest
    {
        public System.Collections.Specialized.NameValueCollection QueryString => null;
        public string this[string key] => null;
    }
    public class HttpServerUtility
    {
        public string MapPath(string path) => null;
    }
}
namespace System.Web.UI
{
    public class Page
    {
        public System.Web.HttpRequest Request => null;
        public System.Web.HttpServerUtility Server => null;
    }
}
