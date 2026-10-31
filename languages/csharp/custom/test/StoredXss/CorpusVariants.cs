using System;
using System.Data;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;

// Sanitized reproductions of additional XSS findings from the synthetic corpus.
namespace CorpusVariants
{
    // -----------------------------------------------------------------------
    // Request data copied into a struct, passed through a service method that
    // builds a message, then written to `InnerHtml` (reflected XSS).
    // -----------------------------------------------------------------------
    public struct TransferResult
    {
        public bool Success;
        public string Message;
    }

    public class TransferRequest
    {
        public string DebitAccount;
        public string CreditAccount;
    }

    public class BankService
    {
        public TransferResult Transfer(TransferRequest details)
        {
            TransferResult result = new TransferResult();
            result.Message = "Transferred from " + details.DebitAccount + " to " + details.CreditAccount;
            return result;
        }
    }

    public class TransferPage : Page
    {
        protected HtmlGenericControl postResp;

        protected void Page_Load(object sender, EventArgs e)
        {
            var details = new TransferRequest();
            details.DebitAccount = Request.Params["debitAccount"]; // $ Source[cs/web/xss]
            details.CreditAccount = Request.Params["creditAccount"]; // $ Source[cs/web/xss]
            TransferResult result = new BankService().Transfer(details);
            postResp.InnerHtml = "<span style='color: Red'>" + result.Message + "</span>"; // $ Alert[cs/web/xss]
            // Safe: encoded.
            postResp.InnerHtml = "<span>" + HttpUtility.HtmlEncode(result.Message) + "</span>";
        }
    }

    // -----------------------------------------------------------------------
    // One page stores request data in a process-wide static field, another
    // page renders it in a Label.
    // -----------------------------------------------------------------------
    public class MessageBoardWriter : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (Request.QueryString["message"] != null)
            {
                MessageBoard.Message = Request.QueryString["message"]; // $ Source[cs/web/xss]
            }
        }
    }

    public class MessageBoard : Page
    {
        public static string Message = "Nothing yet...";

        protected Label lblMessage;

        protected void Page_Load(object sender, EventArgs e)
        {
            lblMessage.Text = Message; // $ Alert[cs/web/xss]
        }
    }

    // -----------------------------------------------------------------------
    // DataSet child rows (comments) concatenated into HTML assigned to Labels.
    // -----------------------------------------------------------------------
    public class ProductPage : Page
    {
        protected Label lblOutput;
        protected Label lblComments;

        public void LoadComments(DataSet ds)
        {
            string output = string.Empty;
            string comments = string.Empty;
            foreach (DataRow prodRow in ds.Tables["products"].Rows)
            {
                output += "<strong>" + prodRow["productName"].ToString() + "</strong>"; // $ Source[cs/web/stored-xss]
                foreach (DataRow commentRow in prodRow.GetChildRows("prod_comments"))
                {
                    comments += "<strong>Email:</strong>" + commentRow["email"] + "<br/>"; // $ Source[cs/web/stored-xss]
                    comments += "<strong>Comment:</strong><br/>" + commentRow["comment"] + "<hr/>"; // $ Source[cs/web/stored-xss]
                }
            }
            lblOutput.Text = output; // $ Alert[cs/web/stored-xss]
            lblComments.Text = comments; // $ Alert[cs/web/stored-xss]
        }
    }

    // -----------------------------------------------------------------------
    // Entity Framework 6 entity formatted with StringBuilder.AppendFormat into
    // a Label.
    // -----------------------------------------------------------------------
    public class BlogEntry
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string Contents { get; set; }
        public string Author { get; set; }
        public DateTime PostedDate { get; set; }
    }

    public class BlogContext : System.Data.Entity.DbContext
    {
        public System.Data.Entity.DbSet<BlogEntry> BlogEntries { get; set; }
    }

    public class BlogEntryRepository
    {
        private readonly BlogContext context = new BlogContext();

        public BlogEntry GetBlogEntry(int id)
        {
            foreach (var b in context.BlogEntries)
                if (b.Id == id)
                    return b;
            return null;
        }
    }

    public class BlogEntryReply : Page
    {
        protected Label lblBlogEntry;
        protected Label lblSafe;

        public void Show(int id)
        {
            var blogEntry = new BlogEntryRepository().GetBlogEntry(id);
            var sb = new StringBuilder();
            sb.Append("<div>");
            sb.AppendFormat("<div class='blogEntryTitle'>{0}</div>", blogEntry.Title); // $ Source[cs/web/stored-xss]
            sb.AppendFormat("<div class='blogEntryContents'>{0}</div>", blogEntry.Contents); // $ Source[cs/web/stored-xss]
            sb.AppendFormat("<div class='blogEntryAuthor'>{0}</div>", blogEntry.Author); // $ Source[cs/web/stored-xss]
            sb.AppendFormat("<div class='blogEntryPostedDate'>{0}</div>", blogEntry.PostedDate);
            sb.Append("</div>");
            lblBlogEntry.Text = sb.ToString(); // $ Alert[cs/web/stored-xss]

            // Safe: encoded, and a DateTime field.
            var safe = new StringBuilder();
            safe.AppendFormat("<div>{0}</div>", HttpUtility.HtmlEncode(blogEntry.Title));
            safe.AppendFormat("<div>{0}</div>", blogEntry.PostedDate);
            lblSafe.Text = safe.ToString();
        }
    }
}
