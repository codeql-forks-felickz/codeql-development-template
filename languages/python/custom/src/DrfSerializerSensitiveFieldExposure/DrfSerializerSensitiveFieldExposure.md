# Sensitive field exposed by a Django REST framework serializer

A Django REST framework `ModelSerializer` (or `HyperlinkedModelSerializer`) returns every field listed in `Meta.fields` (or every model field when `fields = "__all__"`) in API responses, unless the field is write-only. If those fields include sensitive data such as passwords or password hashes, password-reset or API tokens, social security numbers, or dates of birth, any client that can read the resource learns that data. Exposing an active password-reset token can also lead to account takeover.

This query reports model serializers whose readable fields include names that indicate such sensitive data. Fields that are excluded with `Meta.exclude`, marked write-only through `extra_kwargs`, `write_only_fields`, or a declared field with `write_only=True` are not reported.

## Recommendation

List only the fields that clients need in `Meta.fields`. Make fields that clients must submit but never read, such as passwords, write-only. Never return reset tokens or government identifiers in API responses.

## Example

The following serializer exposes a social security number, date of birth, and active password-reset token:

```python
class UserProfileSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = UserProfile
        fields = ("uuid", "image", "reset_token", "reset_token_expiration", "dob", "ssn", "user")
```

Return only non-sensitive fields instead:

```python
class UserProfileSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = UserProfile
        fields = ("uuid", "image", "user")
```

## References

- Django REST framework: [Serializers](https://www.django-rest-framework.org/api-guide/serializers/).
- OWASP API Security Top 10: [API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/).
- Common Weakness Enumeration: [CWE-359](https://cwe.mitre.org/data/definitions/359.html).
- Common Weakness Enumeration: [CWE-200](https://cwe.mitre.org/data/definitions/200.html).
