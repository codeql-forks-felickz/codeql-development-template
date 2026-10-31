using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace WebGoatLike
{
    public class XMLInjection : System.Web.UI.Page
    {
        List<XmlUser> users = new List<XmlUser>();

        protected void Page_Load(object sender, EventArgs e)
        {
            if (Request.QueryString["name"] != null && Request.QueryString["email"] != null)
            {
                users.Add(new XmlUser(Request.QueryString["name"], Request.QueryString["email"]));
                WriteXML();
            }
        }

        private void WriteXML()
        {
            string xml = "<users>";
            foreach (XmlUser user in users)
            {
                xml += "<name>" + user.Name + "</name>";
                xml += "<email>" + user.Email + "</email>";
            }
            xml += "</users>";
            XmlTextWriter writer = new XmlTextWriter(Server.MapPath("/App_Data/u.xml"), Encoding.UTF8);
            writer.WriteRaw(xml);
            writer.Close();
        }

        protected void Direct(object sender, EventArgs e)
        {
            string name = Request.QueryString["name"];
            XmlTextWriter writer = new XmlTextWriter("u.xml", Encoding.UTF8);
            writer.WriteRaw("<name>" + name + "</name>");
        }
    }

    public class XmlUser
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public XmlUser(string name, string email) { Name = name; Email = email; }
    }
}
