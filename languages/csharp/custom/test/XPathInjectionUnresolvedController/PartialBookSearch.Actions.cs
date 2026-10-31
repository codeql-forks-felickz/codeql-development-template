using System.Xml;

namespace Bookstore.Controllers
{
    public partial class PartialBookSearch
    {
        public void Find(string author) // $ Source
        {
            XmlDocument doc = new XmlDocument();
            doc.SelectSingleNode("//book[author='" + author + "']"); // $ Alert
        }
    }
}
