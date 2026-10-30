using System.DirectoryServices;
using Microsoft.AspNetCore.Mvc;

namespace WebFox.Controllers
{
    // Route value concatenated into `DirectorySearcher.Filter`. Already covered
    // by the stock `cs/ldap-injection` query.
    [Route("api/[controller]")]
    [ApiController]
    public class LDAP : ControllerBase
    {
        [HttpGet("{user}")]
        public void LdapInje(string user) // $ Source
        {
            DirectoryEntry de = new DirectoryEntry("LDAP://DC=mycompany,DC=com");
            DirectorySearcher searcher = new DirectorySearcher(de);
            searcher.Filter = "(&(objectClass=user)(|(cn=" + user + ")(sAMAccountName=" + user + ")))"; // $ Alert
            searcher.FindOne();

            // Filter passed through the constructor.
            new DirectorySearcher(de, "(cn=" + user + ")").FindOne(); // $ Alert

            // Constant filter is safe.
            new DirectorySearcher(de, "(objectClass=user)").FindOne();
        }
    }
}
