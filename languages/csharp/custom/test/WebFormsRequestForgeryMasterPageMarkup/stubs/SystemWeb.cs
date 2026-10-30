namespace System.Web.UI
{
    public class Control { }

    public class Page : Control
    {
        public string ViewStateUserKey { get; set; }
    }

    public class MasterPage : Control
    {
        public Page Page { get; }
    }
}
