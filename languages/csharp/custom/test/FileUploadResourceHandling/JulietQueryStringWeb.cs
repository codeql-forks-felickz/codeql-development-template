using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Text;
using System.Web;

namespace Testcases
{
    // CWE-15: External control of system or configuration setting.
    public class CWE15_QueryString_Web
    {
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            string data = req.QueryString["name"]; // $ Source
            using (SqlConnection dbConnection = new SqlConnection("data source=repro;initial catalog=repro;User ID=" + data + ";******")) // $ Alert
            {
                dbConnection.Open();
            }
        }

        public void BadProperty(HttpRequest req, HttpResponse resp)
        {
            string data = req.Params["id"]; // $ Source
            SqlConnection dbConnection = new SqlConnection();
            dbConnection.ConnectionString = "data source=repro;User ID=" + data; // $ Alert
            dbConnection.Open();
        }

        public void BadChangeDatabase(HttpRequest req, HttpResponse resp)
        {
            string data = req.QueryString["db"]; // $ Source
            SqlConnection dbConnection = new SqlConnection("data source=repro");
            dbConnection.ChangeDatabase(data); // $ Alert
        }

        public void Good(HttpRequest req, HttpResponse resp)
        {
            string data = "foo";
            using (SqlConnection dbConnection = new SqlConnection("data source=repro;User ID=" + data))
            {
                dbConnection.Open();
            }
        }

        public void GoodBuilder(HttpRequest req, HttpResponse resp)
        {
            string data = req.QueryString["name"];
            var builder = new SqlConnectionStringBuilder();
            builder.DataSource = "repro";
            builder.UserID = data;
            using (SqlConnection dbConnection = new SqlConnection(builder.ConnectionString))
            {
                dbConnection.Open();
            }
        }
    }

    // CWE-400: Uncontrolled resource consumption (loop bound / write count).
    public class CWE400_QueryString_Web
    {
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            int count = int.Parse(req.QueryString["id"]); // $ Source
            using (StreamWriter sw = new StreamWriter("badSink.txt"))
            {
                for (int i = 0; i < count; i++) // $ Alert
                {
                    sw.WriteLine("Hello");
                }
            }
        }

        public void BadWhile(HttpRequest req, HttpResponse resp)
        {
            int count = int.Parse(req.QueryString["id"]); // $ Source
            int i = 0;
            while (count > i) // $ Alert
            {
                i++;
            }
        }

        public void Good(HttpRequest req, HttpResponse resp)
        {
            int count = int.Parse(req.QueryString["id"]);
            if (count > 0 && count <= 20)
            {
                using (StreamWriter sw = new StreamWriter("goodSink.txt"))
                {
                    for (int i = 0; i < count; i++)
                    {
                        sw.WriteLine("Hello");
                    }
                }
            }
        }

        public void GoodClamp(HttpRequest req, HttpResponse resp)
        {
            int count = Math.Min(int.Parse(req.QueryString["id"]), 20);
            for (int i = 0; i < count; i++)
            {
                Console.WriteLine("Hello");
            }
        }

        public void GoodConstant()
        {
            int count = 20;
            for (int i = 0; i < count; i++)
            {
                Console.WriteLine("Hello");
            }
        }
    }

    // CWE-427: Uncontrolled search path element.
    public class CWE427_QueryString_Web
    {
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            string data = req.QueryString["name"]; // $ Source
            Environment.SetEnvironmentVariable("PATH", data); // $ Alert
        }

        public void BadTarget(HttpRequest req, HttpResponse resp)
        {
            string data = req.QueryString["id"]; // $ Source
            Environment.SetEnvironmentVariable("Path", data, EnvironmentVariableTarget.Process); // $ Alert
        }

        public void Good(HttpRequest req, HttpResponse resp)
        {
            string data = "/bin";
            Environment.SetEnvironmentVariable("PATH", data);
        }

        public void GoodOtherVariable(HttpRequest req, HttpResponse resp)
        {
            string data = req.QueryString["name"];
            Environment.SetEnvironmentVariable("APP_GREETING", data);
        }
    }

    // CWE-789: Memory allocation with excessive size value.
    public class CWE789_QueryString_Web
    {
        public void Bad(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["id"]); // $ Source
            ArrayList intArrayList = new ArrayList(data); // $ Alert
            intArrayList.Add(1);
        }

        public void BadGeneric(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["id"]); // $ Source
            var list = new List<int>(data); // $ Alert
            var sb = new StringBuilder(data); // $ Alert
            var array = new byte[data]; // $ Alert
        }

        public void Good(HttpRequest req, HttpResponse resp)
        {
            int data = int.Parse(req.QueryString["id"]);
            if (data > 0 && data < 100)
            {
                ArrayList intArrayList = new ArrayList(data);
                intArrayList.Add(1);
            }
        }

        public void GoodConstant()
        {
            ArrayList intArrayList = new ArrayList(100);
            intArrayList.Add(1);
        }
    }
}
