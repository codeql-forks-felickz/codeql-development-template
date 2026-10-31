using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Web;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;

namespace Test
{
    // ---------------------------------------------------------------------
    // Entity Framework entities, rendered with Html.Raw (Razor-style view).
    // ---------------------------------------------------------------------
    public class Comment
    {
        public int Id { get; set; }
        public string Body { get; set; }
    }

    public class Product
    {
        public int ProductId { get; set; }
        public string ProductName { get; set; }
        public int Quantity { get; set; }

        // Helpers that interpolate stored fields into HTML.
        public string ToSummaryHtml() => $"<div class=\"product\">{ProductName}</div>"; // $ Source[cs/web/stored-xss]

        public string ToDetailHtml() => "<h1>" + ProductName + "</h1><p>Qty: " + Quantity + "</p>"; // $ Source[cs/web/stored-xss]

        public string ToSafeSummaryHtml() => $"<div class=\"product\">{HttpUtility.HtmlEncode(ProductName)}</div>";
    }

    public class StoreContext : DbContext
    {
        public DbSet<Comment> Comments { get; set; }
        public DbSet<Product> Products { get; set; }
    }

    public class CommentsController
    {
        private readonly StoreContext db = new StoreContext();

        // Remote data is persisted through EF.
        public void Create(Comment comment)
        {
            db.Comments.Add(comment);
            db.SaveChanges();
        }

        public IEnumerable<Comment> Index() => db.Comments;
    }

    // Emulates the code generated for `Views/Comments/Index.cshtml`.
    public class CommentsIndexView
    {
        public void Render(IHtmlHelper Html, IEnumerable<Comment> Model)
        {
            foreach (var item in Model)
            {
                Html.Raw(item.Body); // $ Alert[cs/web/stored-xss]
                // Safe: encoded before being written raw.
                Html.Raw(Html.Encode(item.Body));
                // Safe: integer field.
                Html.Raw(item.Id);
            }
        }
    }

    // ---------------------------------------------------------------------
    // Product pages rendering the helper output into Label / InnerHtml.
    // ---------------------------------------------------------------------
    public class ProductDetails : Page
    {
        protected Label lblSummary;
        protected HtmlGenericControl divDetail;
        protected TextBox txtName;
        protected Label lblSafe;

        public void Show(StoreContext db)
        {
            foreach (var product in db.Products)
            {
                lblSummary.Text = product.ToSummaryHtml(); // $ Alert[cs/web/stored-xss]
                divDetail.InnerHtml = product.ToDetailHtml(); // $ Alert[cs/web/stored-xss]
                // Safe: encoded in the helper.
                lblSafe.Text = product.ToSafeSummaryHtml();
                // Safe: TextBox.Text is HTML encoded when rendered.
                txtName.Text = product.ProductName;
                // Safe: InnerText is HTML encoded when rendered.
                divDetail.InnerText = product.ProductName;
            }
        }
    }

    // ---------------------------------------------------------------------
    // Web Forms page that persists comments through ADO.NET helpers and
    // renders them from a DataSet into a Literal.
    // ---------------------------------------------------------------------
    public class DbProvider
    {
        private readonly DbCommand command;
        private readonly DbDataAdapter adapter;

        public void AddComment(string productCode, string email, string comment)
        {
            command.CommandText = "INSERT INTO Comments VALUES (@p, @e, @c)";
            command.ExecuteNonQuery();
        }

        public DataSet GetCommentsForProduct(string productCode)
        {
            DataSet ds = new DataSet();
            adapter.Fill(ds);
            return ds;
        }

        public DbDataReader GetCommentsReader() => command.ExecuteReader(); // $ Source[cs/web/stored-xss]
    }

    public class StoredXSS : Page
    {
        protected TextBox txtEmail;
        protected TextBox txtComment;
        protected Literal lblComments;
        protected Literal lblSafeComments;
        protected Label lblReaderComments;
        private readonly DbProvider du = new DbProvider();

        protected void btnSave_Click(object sender, EventArgs e)
        {
            du.AddComment("1", txtEmail.Text, txtComment.Text);
            LoadComments();
        }

        protected void LoadComments()
        {
            DataSet ds = du.GetCommentsForProduct("1");
            string comments = string.Empty;
            foreach (DataRow row in ds.Tables[0].Rows)
            {
                comments += "<strong>Email:</strong>" + row["email"] + "<br/>"; // $ Source[cs/web/stored-xss]
                comments += "<strong>Comment:</strong><br/>" + row["comment"] + "<br/><hr/>"; // $ Source[cs/web/stored-xss]
            }
            lblComments.Text = comments; // $ Alert[cs/web/stored-xss]
        }

        protected void LoadCommentsSafe()
        {
            DataSet ds = du.GetCommentsForProduct("1");
            string comments = string.Empty;
            foreach (DataRow row in ds.Tables[0].Rows)
            {
                comments += HttpUtility.HtmlEncode(row.Field<string>("email"));
                comments += HttpUtility.HtmlEncode(row["comment"].ToString());
            }
            lblSafeComments.Text = comments;
        }

        protected void LoadCommentsFromReader()
        {
            DbDataReader reader = du.GetCommentsReader(); // $ Source[cs/web/stored-xss]
            string comments = string.Empty;
            while (reader.Read())
            {
                comments += "<p>" + reader["comment"] + "</p>";
            }
            lblReaderComments.Text = comments; // $ Alert[cs/web/stored-xss]
        }

        // Reflected XSS into a Literal: reported by the standard `cs/web/xss` query
        // once `Literal.Text` is modeled as an HTML sink.
        protected void Search()
        {
            string q = Request.QueryString["q"]; // $ Source[cs/web/xss]
            lblComments.Text = "Results for " + q; // $ Alert[cs/web/xss]
        }
    }
}
