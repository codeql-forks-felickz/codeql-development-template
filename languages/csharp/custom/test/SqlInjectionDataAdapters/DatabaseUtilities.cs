using System;
using System.Web;
using Mono.Data.Sqlite;

namespace WebGoat
{
    public class DatabaseUtilities
    {
        private SqliteConnection GetGoatDBConnection() => new SqliteConnection("Data Source=goat.sqlite");

        private string DoNonQuery(string SQL, SqliteConnection conn)
        {
            var cmd = new SqliteCommand(SQL, conn); // $ Alert
            cmd.ExecuteNonQuery();
            return "";
        }

        // Not called from anywhere in the application, so no remote input can
        // reach these concatenations. `cs/sql-injection` only reports flows from
        // a recognised source, so these must NOT alert on their own.
        public string GetMailingListInfoByEmailAddress(string email)
        {
            string sql = "SELECT FirstName, LastName, Email FROM MailingList where Email = '" + email + "'";
            return DoNonQuery(sql, GetGoatDBConnection());
        }

        public string AddToMailingList(string first, string last, string email)
        {
            string sql = "insert into mailinglist (firstname, lastname, email) values ('" + first + "', '" + last + "', '" + email + "')";
            return DoNonQuery(sql, GetGoatDBConnection());
        }

        // Reachable from a request: shows the `SqliteCommand` sink itself is
        // already covered (it implements `IDbCommand`).
        public string AddNewPosting(string title)
        {
            string sql = "insert into Postings(title) values ('" + title + "')";
            return DoNonQuery(sql, GetGoatDBConnection());
        }
    }

    public class PostingPage : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            new DatabaseUtilities().AddNewPosting(Request.QueryString["title"]); // $ Source
        }
    }
}
