# Uncontrolled data used in path expression (including dynamically resolved constructors)

Accessing files using paths constructed from user-controlled data can allow an attacker to access unexpected resources, such as application configuration files or system files.

This query extends the standard `rb/path-injection` query. In addition to the usual filesystem sinks, it treats the first argument to `new` on a class that is resolved from a string at runtime (via `String#constantize`, `String#safe_constantize` or `Module#const_get`) as a filesystem path. When the class name is not a compile-time constant, an attacker may be able to select `File`, `Dir`, `IO` or `Pathname`, so the constructor argument is opened as a path. Constant class names are only considered when they name one of these filesystem classes.

## Recommendation

Do not resolve classes from user input. If dynamic dispatch is required, map user input to an allow-list of known classes. Validate user-provided paths against an allow-list of permitted files, or normalize them and check that they remain inside an expected directory.

## Example

In the following example, both the class name and the path come from request parameters. A request with `type=File&name=config/database.yml` reads and returns the database configuration:

```ruby
class BenefitFormsController < ActionController::Base
  def download
    path = params[:name]
    file = params[:type].constantize.new(path)
    send_file file, disposition: "attachment"
  end
end
```

The fixed version only allows known file names and does not resolve the class from user input:

```ruby
class BenefitFormsController < ActionController::Base
  ALLOWED_FORMS = %w[benefits.pdf dental.pdf].freeze

  def download
    name = params[:name]
    raise ActionController::BadRequest unless ALLOWED_FORMS.include?(name)
    send_file Rails.root.join("public", "forms", name), disposition: "attachment"
  end
end
```

## References

- OWASP: [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal).
- Common Weakness Enumeration: [CWE-22](https://cwe.mitre.org/data/definitions/22.html).
- Common Weakness Enumeration: [CWE-99](https://cwe.mitre.org/data/definitions/99.html).
