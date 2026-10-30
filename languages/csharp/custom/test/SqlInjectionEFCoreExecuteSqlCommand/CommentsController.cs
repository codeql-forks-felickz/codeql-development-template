using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Blog
{
    public class Comment
    {
        public int Id { get; set; }
        public string Body { get; set; }
        public string Author { get; set; }
    }

    public class CommentContext : DbContext { }

    public class CommentsController : Controller
    {
        private readonly CommentContext _context = new CommentContext();

        // EF Core 2.x: an interpolated string literal binds to the
        // `FormattableString` overload, which EF Core turns into a
        // parameterized command (`{x}` -> `@p0`), so this is NOT SQL injection.
        [HttpPost]
        public async Task<IActionResult> CreateInterpolated([Bind("Id,Body,Author")] Comment comment)
        {
            await _context.Database.ExecuteSqlCommandAsync(
                $"insert into comments (Id, Body, Author) values ('{comment.Id}', '{comment.Body}', '{comment.Author}')");
            _context.Database.ExecuteSqlCommand(
                $"insert into comments (Id, Body, Author) values ('{comment.Id}', '{comment.Body}', '{comment.Author}')");
            return RedirectToAction("Index");
        }

        // EF Core 2.x: string concatenation binds to the `RawSqlString` overload.
        [HttpPost]
        public async Task<IActionResult> CreateConcatenated([Bind("Id,Body,Author")] Comment comment) // $ Source
        {
            await _context.Database.ExecuteSqlCommandAsync(
                "insert into comments (Id, Body, Author) values ('" + comment.Id + "', '" + comment.Body + "', '" + comment.Author + "')"); // $ Alert
            _context.Database.ExecuteSqlCommand(
                "insert into comments (Id, Body, Author) values ('" + comment.Id + "', '" + comment.Body + "', '" + comment.Author + "')"); // $ Alert
            return RedirectToAction("Index");
        }

        // EF Core 2.x: an interpolated string first stored in a `string`
        // is already formatted, so it binds to the `RawSqlString` overload.
        [HttpPost]
        public async Task<IActionResult> CreateInterpolatedViaString([Bind("Id,Body,Author")] Comment comment) // $ Source
        {
            string sql = $"insert into comments (Id, Body, Author) values ('{comment.Id}', '{comment.Body}', '{comment.Author}')";
            await _context.Database.ExecuteSqlCommandAsync(sql); // $ Alert
            _context.Database.ExecuteSqlCommand(sql); // $ Alert
            await _context.Database.ExecuteSqlCommandAsync(string.Format("delete from comments where Author = '{0}'", comment.Author)); // $ Alert
            return RedirectToAction("Index");
        }

        // EF Core 2.x: parameterized `RawSqlString` overload with constant SQL is safe.
        [HttpPost]
        public async Task<IActionResult> CreateParameterized([Bind("Id,Body,Author")] Comment comment)
        {
            await _context.Database.ExecuteSqlCommandAsync(
                "insert into comments (Id, Body, Author) values ({0}, {1}, {2})", comment.Id, comment.Body, comment.Author);
            return RedirectToAction("Index");
        }

        // EF Core 3.0+ APIs.
        [HttpPost]
        public async Task<IActionResult> CreateEfCore3([Bind("Id,Body,Author")] Comment comment) // $ Source
        {
            await _context.Database.ExecuteSqlRawAsync(
                "insert into comments (Body) values ('" + comment.Body + "')"); // $ Alert
            _context.Database.ExecuteSqlRaw($"insert into comments (Body) values ('{comment.Body}')"); // $ Alert
            await _context.Database.ExecuteSqlInterpolatedAsync(
                $"insert into comments (Body) values ({comment.Body})");
            _context.Database.ExecuteSqlInterpolated($"insert into comments (Body) values ({comment.Body})");
            await _context.Database.ExecuteSqlRawAsync(
                "insert into comments (Body) values ({0})", comment.Body);
            return RedirectToAction("Index");
        }
    }
}
