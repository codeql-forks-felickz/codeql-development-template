// Sanitized reproduction: blog MVC controller with no authorization anywhere in the application.
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace Blog.Controllers
{
    public class Comment
    {
        public int Id;
        public string Body;
        public string Author;
    }

    public class CommentStore
    {
        public Comment Find(int id) => null;
        public void Add(Comment c) { }
        public void Update(Comment c) { }
        public void Remove(Comment c) { }
        public bool Exists(int id) => false;
    }

    public class CommentsController : Controller
    {
        private readonly CommentStore _store = new CommentStore();

        public IActionResult Index() => View();

        public IActionResult Details(int? id) => View(_store.Find(id.Value));

        // BAD: anyone can create comments.
        [HttpPost]
        public IActionResult Create([Bind("Id,Body,Author")] Comment comment) // $ Alert[cs/web/missing-authentication-state-changing-action]
        {
            _store.Add(comment);
            return RedirectToAction("Index");
        }

        // GET form for editing: read-only, not reported by the new query.
        public IActionResult Edit(int? id) => View(_store.Find(id.Value));

        // BAD: anyone can edit any comment by ID.
        [HttpPost]
        public IActionResult Edit(int id, [Bind("Id,Body,Author")] Comment comment) // $ Alert[cs/web/missing-function-level-access-control] Alert[cs/web/insecure-direct-object-reference]
        {
            if (id != comment.Id)
                return NotFound();
            _store.Update(comment);
            return RedirectToAction("Index");
        }

        public IActionResult Delete(int? id) => View(_store.Find(id.Value));

        // BAD: anyone can delete any comment by ID.
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public IActionResult DeleteConfirmed(int id) // $ Alert[cs/web/missing-function-level-access-control] Alert[cs/web/insecure-direct-object-reference]
        {
            _store.Remove(_store.Find(id));
            return RedirectToAction("Index");
        }
    }
}
