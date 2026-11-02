# Mass assignment of user-controlled ownership or privilege field

Rails strong parameters (`params.require(...).permit(...)`) restrict which request attributes may be mass-assigned to a model. The built-in `rb/insecure-mass-assignment` query reports cases where arbitrary attributes are permitted (for example `permit!` or `to_unsafe_h`), but treats any explicit allowlist as safe.

An explicit allowlist is still insecure when it contains an attribute that identifies the owner of a record (such as `creator_id`, `user_id` or `owner_id`) or grants privileges (such as `admin` or `role`). An authenticated user can then create or update records on behalf of another user, or escalate their own privileges (CWE-639, authorization bypass through user-controlled key).

This query reports ActiveRecord mass-assignment calls (`create`, `new`, `update`, ...) whose argument comes from a `permit` call on request parameters that allows such a field, unless the field is overridden server-side (`merge(creator_id: current_user.id)`, `record.creator_id = ...` on the mass-assigned record in the same method) or removed (`except(:creator_id)`).

## Recommendation

Do not permit ownership or privilege attributes from the request. Set them on the server from the authenticated user, for example with `current_user.id`, or build the record through an association of the current user.

## Known limitations

`merge` and `except` barriers apply to the whole permit result rather than individual fields, so overriding or removing one sensitive field can suppress reporting for other permitted sensitive fields. Creating through an association, such as `current_user.messages.create(...)`, is not exempted.

## Example

In the following example, a user can send a message that appears to come from any other user:

```ruby
class MessagesController < ApplicationController
  def create
    Message.create(message_params)
  end

  private

  def message_params
    params.require(:message).permit(:creator_id, :message, :receiver_id)
  end
end
```

Remove `creator_id` from the allowlist and set it from the authenticated user:

```ruby
class MessagesController < ApplicationController
  def create
    Message.create(message_params.merge(creator_id: current_user.id))
  end

  private

  def message_params
    params.require(:message).permit(:message, :receiver_id)
  end
end
```

## References

- Rails Guides: [Strong Parameters](https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters).
- OWASP: [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-639](https://cwe.mitre.org/data/definitions/639.html).
- Common Weakness Enumeration: [CWE-915](https://cwe.mitre.org/data/definitions/915.html).
