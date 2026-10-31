// Sanitized reproduction: async blog-entry MVC controller with no authorization anywhere in the
// application. Anti-forgery validation is present but does not restrict who can call the actions.
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace Blog.Controllers
{
    public class BlogEntry
    {
        public int Id;
        public string Title;
        public string Body;
    }

    public class ConcurrencyException : Exception { }

    public class BlogEntryContext
    {
        public Task<BlogEntry> FindAsync(int id) => Task.FromResult<BlogEntry>(null);
        public void Add(BlogEntry e) { }
        public void Update(BlogEntry e) { }
        public void Remove(BlogEntry e) { }
        public bool Any(int id) => false;
        public Task<int> SaveChangesAsync() => Task.FromResult(0);
    }

    public class BlogEntriesController : Controller
    {
        private readonly BlogEntryContext _context = new BlogEntryContext();

        public async Task<IActionResult> Details(int? id) => View(await _context.FindAsync(id.Value));

        // BAD: anyone can create posts.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,Title,Body")] BlogEntry blogEntry) // $ Alert[cs/web/missing-authentication-state-changing-action]
        {
            _context.Add(blogEntry);
            await _context.SaveChangesAsync();
            return RedirectToAction("Index");
        }

        // BAD: anyone can edit any post by ID.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,Title,Body")] BlogEntry blogEntry) // $ Alert[cs/web/missing-function-level-access-control] Alert[cs/web/insecure-direct-object-reference]
        {
            if (id != blogEntry.Id)
                return NotFound();
            try
            {
                _context.Update(blogEntry);
                await _context.SaveChangesAsync();
            }
            catch (ConcurrencyException)
            {
                if (!BlogEntryExists(blogEntry.Id))
                    return NotFound();
                throw;
            }
            return RedirectToAction("Index");
        }

        // BAD: anyone can delete any post by ID.
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id) // $ Alert[cs/web/missing-function-level-access-control] Alert[cs/web/insecure-direct-object-reference]
        {
            var blogEntry = await _context.FindAsync(id);
            _context.Remove(blogEntry);
            await _context.SaveChangesAsync();
            return RedirectToAction("Index");
        }

        private bool BlogEntryExists(int id) => _context.Any(id);
    }
}
