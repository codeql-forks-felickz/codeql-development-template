using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace App
{
    public class User
    {
        public int ID;
        public string name;
        public string role;
        public string password;
    }

    public class UserStore
    {
        public User Find(int id) => null;
        public List<User> All() => null;
        public void Update(User u) { }
        public void Remove(User u) { }
    }

    [Route("api/[controller]")]
    public class UsersController : Controller
    {
        private readonly UserStore _store = new UserStore();
        private readonly IAuthorizationService _authz;

        // BAD: only requires an authenticated caller; any user can overwrite any account (incl. role).
        [Authorize]
        [HttpPut("{id}")]
        public IActionResult Put(int id, [FromBody] User user) // $ Alert[cs/web/insecure-direct-object-reference-authorize-only]
        {
            var existing = _store.Find(id);
            if (existing == null)
                return NotFound();
            existing.name = user.name;
            existing.role = user.role;
            existing.password = user.password;
            _store.Update(existing);
            return Ok(existing);
        }

        // BAD: only requires an authenticated caller; any user can delete any account.
        [Authorize]
        [HttpDelete("{id}")]
        public IActionResult Delete(int id) // $ Alert[cs/web/insecure-direct-object-reference-authorize-only]
        {
            var user = _store.Find(id);
            if (user == null)
                return NotFound();
            _store.Remove(user);
            return Ok(user);
        }

        // BAD: `Authorize` that only selects an authentication scheme does not restrict who may edit.
        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpPatch("{userId}")]
        public IActionResult UpdateUser(int userId, [FromBody] User user) // $ Alert[cs/web/insecure-direct-object-reference-authorize-only]
        {
            var existing = _store.Find(userId);
            existing.name = user.name;
            _store.Update(existing);
            return Ok(existing);
        }

        // GOOD: ownership check against the current principal.
        [Authorize]
        [HttpPut("{id}/profile")]
        public IActionResult UpdateProfile(int id, [FromBody] User user)
        {
            var existing = _store.Find(id);
            if (existing.name != User.Identity.Name)
                return Forbid();
            existing.name = user.name;
            _store.Update(existing);
            return Ok(existing);
        }

        // GOOD: role check in code.
        [Authorize]
        [HttpDelete("{id}/force")]
        public IActionResult ForceDelete(int id)
        {
            if (!User.IsInRole("Administrator"))
                return Forbid();
            _store.Remove(_store.Find(id));
            return Ok(null);
        }

        // GOOD: restricted to a role by the attribute.
        [Authorize(Roles = "Administrator")]
        [HttpDelete("{id}/admin")]
        public IActionResult RemoveAccount(int id)
        {
            _store.Remove(_store.Find(id));
            return Ok(null);
        }

        // GOOD: restricted by an authorization policy.
        [Authorize("OwnerOnly")]
        [HttpPut("{id}/email")]
        public IActionResult ChangeEmail(int id, [FromBody] User user)
        {
            var existing = _store.Find(id);
            existing.name = user.name;
            _store.Update(existing);
            return Ok(existing);
        }

        // GOOD: resource-based authorization.
        [Authorize]
        [HttpDelete("v2/{id}")]
        public async Task<IActionResult> DeleteV2(int id)
        {
            var user = _store.Find(id);
            var result = await _authz.AuthorizeAsync(User, user, "Owner");
            if (!result.Succeeded)
                return Forbid();
            _store.Remove(user);
            return Ok(user);
        }

        // GOOD: ownership enforced in the lookup predicate.
        [Authorize]
        [HttpDelete("mine/{id}")]
        public IActionResult DeleteMine(int id)
        {
            var user = _store.All().Find(u => u.ID == id && u.name == User.Identity.Name);
            if (user == null)
                return NotFound();
            _store.Remove(user);
            return Ok(user);
        }

        // GOOD: read-only action.
        [Authorize]
        [HttpGet("{id}")]
        public IActionResult Get(int id)
        {
            return Ok(_store.Find(id));
        }

        // GOOD (for this query): no `Authorize` at all; this case is reported by the
        // existing `cs/web/insecure-direct-object-reference` and
        // `cs/web/missing-function-level-access-control` queries instead.
        [HttpDelete("legacy/{id}")]
        public IActionResult DeleteLegacy(int id) // $ Alert[cs/web/insecure-direct-object-reference] Alert[cs/web/missing-function-level-access-control]
        {
            _store.Remove(_store.Find(id));
            return Ok(null);
        }
    }

    // GOOD: the controller is restricted to a role, so method-level `[Authorize]` only adds to it.
    [Authorize(Roles = "Administrator")]
    [Route("api/admin/users")]
    public class ManageUsersController : Controller
    {
        private readonly UserStore _store = new UserStore();

        [Authorize]
        [HttpDelete("{id}")]
        public IActionResult Delete(int id)
        {
            _store.Remove(_store.Find(id));
            return Ok(null);
        }
    }
}
