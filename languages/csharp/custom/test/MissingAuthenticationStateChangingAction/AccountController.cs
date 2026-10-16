// `[AllowAnonymous]` takes precedence over a controller-level `[Authorize]`.
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Blog.Controllers
{
    [Authorize]
    [Route("api/accounts")]
    public class AccountsController : Controller
    {
        private readonly UserContext _context = new UserContext();

        // BAD: `[AllowAnonymous]` overrides the controller-level `[Authorize]`, so anyone can
        // delete any account. The stock query treats the controller `[Authorize]` as sufficient.
        [AllowAnonymous]
        [HttpDelete("{id}")]
        public IActionResult DeleteAccount(int id) // $ Alert[cs/web/missing-authentication-state-changing-action]
        {
            _context.Remove(_context.FindUser(id));
            return Ok(null);
        }

        // GOOD: anonymous by design, does not act on an existing resource by ID.
        [AllowAnonymous]
        [HttpPost("signup")]
        public IActionResult CreateAccount([FromBody] BlogUser user)
        {
            _context.Add(user);
            return Ok(null);
        }

        // GOOD: protected by the controller-level `[Authorize]`.
        [HttpDelete("me/{id}")]
        public IActionResult RemoveAccount(int id)
        {
            _context.Remove(_context.FindUser(id));
            return Ok(null);
        }
    }

    // GOOD: protected by a role-restricted `[Authorize]`.
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly UserContext _context = new UserContext();

        [HttpPost]
        public IActionResult Ban(int id)
        {
            _context.Remove(_context.FindUser(id));
            return Ok(null);
        }
    }
}
