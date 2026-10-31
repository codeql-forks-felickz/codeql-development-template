using System;
using System.Web.UI;

namespace WebGoat
{
    public class TracePage : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // BAD: any visitor can turn on tracing with `?trace=true`.
            if (Request["trace"] == "true")
            {
                Trace.IsEnabled = true; // $ Alert
            }
        }
    }

    public class AlwaysTracePage : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // BAD: tracing is always enabled.
            Trace.IsEnabled = true; // $ Alert
        }
    }

    public class LocalTracePage : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // GOOD: tracing is only enabled for requests from the local machine.
            if (Request.IsLocal)
            {
                Trace.IsEnabled = true;
            }
        }
    }

    public class NoTracePage : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // GOOD: tracing is disabled.
            Trace.IsEnabled = false;
        }
    }
}
