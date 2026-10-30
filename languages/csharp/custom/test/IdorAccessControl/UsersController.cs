using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Api
{
    public class User
    {
        public int ID { get; set; }
        public string email { get; set; }
    }

    public class UserUpdateRequest
    {
        public string email { get; set; }
    }

    public class DataContext : DbContext
    {
        public DbSet<User> Users { get; set; }
    }

    // `[Authorize]` only authenticates the caller; nothing checks that the
    // caller owns the record selected by `{id}`.
    [Route("api/[controller]")]
    public class UsersController : Controller
    {
        private readonly DataContext _context;

        public UsersController(DataContext context)
        {
            _context = context;
        }

        [Authorize]
        [HttpGet("{id}")]
        public IActionResult Get(int id) // $ Source
        {
            return Ok(_context.Users.Find(id)); // $ Alert
        }

        [Authorize]
        [HttpPut("{id}")]
        public IActionResult Put(int id, [FromBody] UserUpdateRequest user) // $ Source
        {
            var existingUser = _context.Users.SingleOrDefault(m => m.ID == id); // $ Alert
            if (existingUser == null)
            {
                return NotFound();
            }
            existingUser.email = user.email;
            _context.Users.Update(existingUser);
            _context.SaveChanges();
            return Ok(existingUser);
        }

        [Authorize]
        [HttpDelete("{id}")]
        public IActionResult Delete(int id) // $ Source
        {
            User user = _context.Users.SingleOrDefault(m => m.ID == id); // $ Alert
            if (user == null)
            {
                return NotFound();
            }
            _context.Users.Remove(user);
            _context.SaveChanges();
            return Ok(user);
        }
    }

    [Route("api/[controller]")]
    public class SafeUsersController : Controller
    {
        private readonly DataContext _context;

        public SafeUsersController(DataContext context)
        {
            _context = context;
        }

        // Safe: the requested id is compared with the authenticated principal.
        [Authorize]
        [HttpPut("{id}")]
        public IActionResult Put(int id, [FromBody] UserUpdateRequest user)
        {
            if (User.FindFirst("sub")?.Value != id.ToString())
            {
                return Forbid();
            }
            var existingUser = _context.Users.SingleOrDefault(m => m.ID == id);
            existingUser.email = user.email;
            _context.SaveChanges();
            return Ok(existingUser);
        }

        // Safe: only administrators may delete arbitrary users.
        [Authorize(Roles = "Administrator")]
        [HttpDelete("{id}")]
        public IActionResult Delete(int id)
        {
            User user = _context.Users.SingleOrDefault(m => m.ID == id);
            _context.Users.Remove(user);
            _context.SaveChanges();
            return Ok(user);
        }

        // Not an identifier: not a direct object reference.
        [HttpGet("search")]
        public IActionResult Search(string email)
        {
            return Ok(_context.Users.Where(m => m.email == email).ToList());
        }

        // Safe: the current user is checked in a sibling lambda in the query chain.
        [Authorize]
        [HttpGet("{id}")]
        public IActionResult GetOwned(int id)
        {
            var user = _context.Users
                .Where(m => m.email == User.Identity.Name)
                .SingleOrDefault(m => m.ID == id);
            return Ok(user);
        }

        // Safe: the service scopes the lookup to the current user.
        [Authorize]
        [HttpGet("{id}")]
        public IActionResult GetFromService(int id)
        {
            return Ok(new OwnedUserService().Get(id));
        }
    }

    public class OwnedUserService
    {
        private readonly DataContext _context;
        public System.Security.Principal.IPrincipal User { get; set; }

        public User Get(int id)
        {
            string userName = User.Identity.Name;
            return _context.Users
                .Where(m => m.email == userName)
                .SingleOrDefault(m => m.ID == id);
        }
    }
}
