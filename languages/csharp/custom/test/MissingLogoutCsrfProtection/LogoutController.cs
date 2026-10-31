using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace Accounts
{
    [Authorize]
    public class AccountController : Controller
    {
        public async Task<IActionResult> Logout() // $ Alert[cs/web/missing-logout-csrf-protection]
        {
            await HttpContext.SignOutAsync();
            return null;
        }

        [HttpPost]
        // lgtm [cs/web/missing-token-validation]
        public async Task<IActionResult> PostOnlyLogout() // $ Alert[cs/web/missing-logout-csrf-protection]
        {
            await HttpContext.SignOutAsync();
            return null;
        }

        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ValidatedLogout()
        {
            await HttpContext.SignOutAsync();
            return null;
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ProtectedLogout()
        {
            await HttpContext.SignOutAsync();
            return null;
        }
    }
}
