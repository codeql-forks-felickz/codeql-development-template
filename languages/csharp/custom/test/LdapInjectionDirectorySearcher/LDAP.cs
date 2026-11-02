using Microsoft.AspNetCore.Mvc;
using System.DirectoryServices;

namespace WebFox.Controllers
{
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
            SearchResult result = searcher.FindOne();
        }

        // GOOD: the user name is escaped before it is used in the filter.
        [HttpGet("safe/{user}")]
        public void LdapSafe(string user)
        {
            DirectoryEntry de = new DirectoryEntry("LDAP://DC=mycompany,DC=com");
            DirectorySearcher searcher = new DirectorySearcher(de);
            searcher.Filter = "(&(objectClass=user)(cn=" + LdapFilterEncode(user) + "))";
            SearchResult result = searcher.FindOne();
        }

        private static string LdapFilterEncode(string value) => value;

        // GOOD: a numeric value cannot change the filter.
        [HttpGet("id/{id}")]
        public void LdapById(int id)
        {
            DirectoryEntry de = new DirectoryEntry("LDAP://DC=mycompany,DC=com");
            DirectorySearcher searcher = new DirectorySearcher(de);
            searcher.Filter = "(&(objectClass=user)(employeeID=" + id + "))";
            SearchResult result = searcher.FindOne();
        }
    }
}
