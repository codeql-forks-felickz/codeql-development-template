using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Cwe256.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Salt { get; set; }
        public string Password { get; set; }
    }

    public class Article
    {
        public int Id { get; set; }
        public string Title { get; set; }
    }

    public class UserContext : DbContext
    {
        public DbSet<User> User { get; set; }
        public DbSet<Article> Article { get; set; }
    }

    public interface ICryptographicService
    {
        string HashPassword(string password, string salt);
    }
}

namespace Cwe256.Controllers
{
    using Cwe256.Models;

    public class UsersController : Controller
    {
        private readonly UserContext _context;
        private readonly ICryptographicService _crypto;

        public UsersController(UserContext context, ICryptographicService crypto)
        {
            _context = context;
            _crypto = crypto;
        }

        // Safe: the password is replaced by a hash before the entity is persisted.
        [HttpPost]
        public async Task<IActionResult> Create([Bind("Id,Username,Password")] User user)
        {
            user.Salt = Guid.NewGuid().ToString("N");
            user.Password = _crypto.HashPassword(user.Password, user.Salt);
            _context.Add(user);
            await _context.SaveChangesAsync();
            return RedirectToAction("Index");
        }

        // CWE-256: the model-bound password is persisted verbatim.
        [HttpPost]
        public async Task<IActionResult> Edit(int id, [Bind("Id,Username,Password")] User user)
        {
            _context.Update(user); // $ Alert
            await _context.SaveChangesAsync();
            return RedirectToAction("Index");
        }

        // CWE-256: same, through the DbSet.
        [HttpPost]
        public IActionResult Register(User user)
        {
            _context.User.Add(user); // $ Alert
            _context.SaveChanges();
            return RedirectToAction("Index");
        }

        // Safe: the entity type has no credential property.
        [HttpPost]
        public IActionResult Publish(Article article)
        {
            _context.Update(article);
            _context.SaveChanges();
            return RedirectToAction("Index");
        }
    }
}
