// Mirrors the C# that the Razor source generator emits for MVC views
// (verified against generated `*_cshtml.g.cs` output from a build-mode none database).
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.TagHelpers;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.TagHelpers;

namespace Cwe200.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class LoginModel
    {
        public string Username { get; set; }
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}

namespace AspNetCoreGeneratedDocument
{
    internal sealed class Views_Users_Details : RazorPage<Cwe200.Models.User>
    {
        public IHtmlHelper<Cwe200.Models.User> Html { get; private set; }

        public override async System.Threading.Tasks.Task ExecuteAsync()
        {
            Write(Html.DisplayNameFor(model => model.Password));
            Write(Html.DisplayFor(model => model.Password)); // $ Alert
            Write(Html.DisplayFor(model => model.Username));
            Write(Model.Password); // $ Alert
            Write(Model.Username);
            Write(Html.PasswordFor(model => model.Password, null));
            Write(Html.TextBoxFor(model => model.Password, null, null)); // $ Alert
        }
    }

    internal sealed class Views_Users_Edit : RazorPage<Cwe200.Models.User>
    {
        private static readonly TagHelperAttribute __tagHelperAttribute_0 = new TagHelperAttribute("class", "form-control", HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly TagHelperAttribute __tagHelperAttribute_1 = new TagHelperAttribute("type", "password", HtmlAttributeValueStyle.DoubleQuotes);

        private LabelTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_LabelTagHelper;
        private InputTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_InputTagHelper;

        public IModelExpressionProvider ModelExpressionProvider { get; private set; }

        public override async System.Threading.Tasks.Task ExecuteAsync()
        {
            // <label asp-for="Password"></label>
            __Microsoft_AspNetCore_Mvc_TagHelpers_LabelTagHelper = new LabelTagHelper();
            __Microsoft_AspNetCore_Mvc_TagHelpers_LabelTagHelper.For = ModelExpressionProvider.CreateModelExpression(ViewData, __model => __model.Password);
            // <input asp-for="Password" class="form-control" />
            __Microsoft_AspNetCore_Mvc_TagHelpers_InputTagHelper = new InputTagHelper();
            __Microsoft_AspNetCore_Mvc_TagHelpers_InputTagHelper.For = ModelExpressionProvider.CreateModelExpression(ViewData, __model => __model.Password); // $ Alert
            WriteLiteral(__tagHelperAttribute_0);
            // <input asp-for="Password" type="password" class="form-control" />
            __Microsoft_AspNetCore_Mvc_TagHelpers_InputTagHelper = new InputTagHelper();
            __Microsoft_AspNetCore_Mvc_TagHelpers_InputTagHelper.For = ModelExpressionProvider.CreateModelExpression(ViewData, __model => __model.Password);
            __Microsoft_AspNetCore_Mvc_TagHelpers_InputTagHelper.InputTypeName = (string)__tagHelperAttribute_1.Value;
            WriteLiteral(__tagHelperAttribute_0);
            // <input asp-for="Username" class="form-control" />
            __Microsoft_AspNetCore_Mvc_TagHelpers_InputTagHelper = new InputTagHelper();
            __Microsoft_AspNetCore_Mvc_TagHelpers_InputTagHelper.For = ModelExpressionProvider.CreateModelExpression(ViewData, __model => __model.Username);
            WriteLiteral(__tagHelperAttribute_0);
        }
    }

    internal sealed class Views_Account_Login : RazorPage<Cwe200.Models.LoginModel>
    {
        private InputTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_InputTagHelper;

        public IModelExpressionProvider ModelExpressionProvider { get; private set; }

        public override async System.Threading.Tasks.Task ExecuteAsync()
        {
            // Safe: [DataType(DataType.Password)] makes the input tag helper render type="password" without a value.
            __Microsoft_AspNetCore_Mvc_TagHelpers_InputTagHelper = new InputTagHelper();
            __Microsoft_AspNetCore_Mvc_TagHelpers_InputTagHelper.For = ModelExpressionProvider.CreateModelExpression(ViewData, __model => __model.Password);
        }
    }
}
