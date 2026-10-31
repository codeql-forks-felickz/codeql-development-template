using System;
using System.Collections.Generic;
using System.Security;
using System.Text;
using System.Xml;

namespace XmlInjectionFileWrite
{
    public class XmlUser
    {
        public string Name { get; set; }
        public string Email { get; set; }

        public XmlUser(string name, string email)
        {
            Name = name;
            Email = email;
        }
    }

    // Query string values are stored on a page field and later concatenated
    // into raw XML that is written to a shared file.
    public class XmlUsers : System.Web.UI.Page
    {
        List<XmlUser> users;

        protected void Page_Load(object sender, EventArgs e)
        {
            users = new List<XmlUser>();
            if (Request.QueryString["name"] != null && Request.QueryString["email"] != null)
            {
                users.Add(new XmlUser(Request.QueryString["name"], Request.QueryString["email"])); // $ Source
                WriteXml();
            }
        }

        private void WriteXml()
        {
            string xml = "<?xml version=\"1.0\" standalone=\"yes\"?>" + Environment.NewLine + "<users>" + Environment.NewLine;
            foreach (XmlUser user in users)
            {
                xml += "<user>" + Environment.NewLine;
                xml += "<name>" + user.Name + "</name>" + Environment.NewLine;
                xml += "<email>" + user.Email + "</email>" + Environment.NewLine;
                xml += "</user>" + Environment.NewLine;
            }
            xml += "</users>" + Environment.NewLine;

            XmlTextWriter writer = new XmlTextWriter(Server.MapPath("/App_Data/users.xml"), Encoding.UTF8);
            writer.WriteRaw(xml); // $ Alert
            writer.Close();
        }

        // GOOD: the values are escaped before being written as raw XML.
        protected void AddEscaped(object sender, EventArgs e)
        {
            string name = SecurityElement.Escape(Request.QueryString["name"]);
            XmlTextWriter writer = new XmlTextWriter(Server.MapPath("/App_Data/users.xml"), Encoding.UTF8);
            writer.WriteRaw("<user><name>" + name + "</name></user>");
            writer.Close();
        }

        // GOOD: `WriteElementString` escapes the value.
        protected void AddWithWriter(object sender, EventArgs e)
        {
            XmlTextWriter writer = new XmlTextWriter(Server.MapPath("/App_Data/users.xml"), Encoding.UTF8);
            writer.WriteStartElement("user");
            writer.WriteElementString("name", Request.QueryString["name"]);
            writer.WriteEndElement();
            writer.Close();
        }
    }
}
