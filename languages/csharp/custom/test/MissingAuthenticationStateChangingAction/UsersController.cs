// Sanitized reproduction: user management MVC controller with no authorization anywhere in the application.
using Microsoft.AspNetCore.Mvc;

namespace Blog.Controllers
{
    public class BlogUser
    {
        public int Id;
        public string Username;
        public string Password;
    }

    public class UserContext
    {
        public BlogUser FindUser(int id) => null;
        public void Add(BlogUser u) { }
        public void Update(BlogUser u) { }
        public void Remove(BlogUser u) { }
    }

    public class UsersController : Controller
    {
        private readonly UserContext _context = new UserContext();

        public IActionResult Index() => View();

        // BAD: anyone can create users.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Create([Bind("Id,Username,Password")] BlogUser user) // $ Alert[cs/web/missing-authentication-state-changing-action]
        {
            _context.Add(user);
            return RedirectToAction("Index");
        }

        // BAD: anyone can modify any user by ID. The stock IDOR query treats the call to
        // `UserExists` as a check against the current user.
        [HttpPost]
        public IActionResult Edit(int id, [Bind("Id,Username,Password")] BlogUser user) // $ Alert[cs/web/missing-function-level-access-control]
        {
            if (id != user.Id || !UserExists(id))
                return NotFound();
            _context.Update(user);
            return RedirectToAction("Index");
        }

        // BAD: anyone can delete any user by ID.
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public IActionResult DeleteConfirmed(int id) // $ Alert[cs/web/missing-function-level-access-control]
        {
            var user = _context.FindUser(id);
            _context.Remove(user);
            return RedirectToAction("Index");
        }

        // GOOD: authentication flows are expected to be anonymous.
        [HttpPost]
        public IActionResult Login(string username, string password) => RedirectToAction("Index");

        [HttpPost]
        public IActionResult Register([Bind("Username,Password")] BlogUser user)
        {
            _context.Add(user);
            return RedirectToAction("Index");
        }

        private bool UserExists(int id) => _context.FindUser(id) != null;
    }
}
