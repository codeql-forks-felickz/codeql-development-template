// Reproduction of an ASP.NET Core API controller that concatenates route and form
// parameters into MySQL command text (unguard membership-service pattern).

using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using MySql.Data.MySqlClient;

namespace AspNetCoreMembership
{
    [ApiController]
    [Route("[controller]")]
    public class MembershipController : ControllerBase
    {
        private readonly MySqlConnection connection = new MySqlConnection("Server=db");

        [HttpGet("{userid}")]
        public async Task<IActionResult> GetMembershipStatus(string userid) // $ Source
        {
            string selectQuery = "SELECT membership FROM membership WHERE userid = " + userid;
            var selectCommand = new MySqlCommand(selectQuery, connection); // $ Alert
            var membership = await selectCommand.ExecuteScalarAsync();
            if (membership == null)
            {
                string insertQuery = $@"INSERT INTO membership (userid, membership) VALUES ({userid}, ""FREE"")";
                var insertCommand = new MySqlCommand(insertQuery, connection); // $ Alert
                await insertCommand.ExecuteNonQueryAsync();
            }
            return Ok(membership);
        }

        [HttpPost("add/{userid}")]
        public async Task<IActionResult> SetMembershipStatus(string userid, [FromForm(Name = "membership")] string membership) // $ Source
        {
            string query = "INSERT INTO membership (userid, membership) VALUES (" + userid + ", '" + membership + "') ON DUPLICATE KEY UPDATE membership = '" + membership + "'";
            var command = new MySqlCommand(query, connection); // $ Alert
            await command.ExecuteNonQueryAsync();
            return Ok(membership);
        }

        [HttpGet("safe")]
        public async Task<IActionResult> GetAllMemberships()
        {
            var command = new MySqlCommand("SELECT userid, membership FROM membership", connection);
            return Ok(await command.ExecuteScalarAsync());
        }
    }
}
