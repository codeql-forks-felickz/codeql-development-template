using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace WebFox.Controllers
{
    // Route value concatenated into `SqlCommand` text. Already covered by the
    // stock `cs/sql-injection` query.
    [ApiController]
    [Route("[controller]")]
    public class Sqli : ControllerBase
    {
        [HttpGet("{id}")]
        public string DoSqli(string id) // $ Source
        {
            using (SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE userId = '" + id + "'")) // $ Alert
            {
                cmd.ExecuteReader();
            }
            // Constant SQL is safe.
            using (SqlCommand cmd = new SqlCommand("SELECT * FROM users"))
            {
                cmd.ExecuteReader();
            }
            return "";
        }
    }
}
