Some library APIs evaluate a string argument as Python code. Passing user-controlled text to such an API allows a malicious user to execute arbitrary code. This query reuses the sources and sanitizers of the standard `py/code-injection` query, and adds sinks for code-evaluating APIs that the standard query does not model:

- Pillow's `PIL.ImageMath.eval` and `PIL.ImageMath.unsafe_eval`, which pass the `expression` argument to Python's `eval`. The restricted environment used by `ImageMath.eval` has been escaped in several Pillow releases (for example CVE-2022-22817 and CVE-2023-50447), and `unsafe_eval` makes no attempt at restriction.

Only results at these additional sinks are reported, so this query complements `py/code-injection` without duplicating its results.

## Recommendation

Do not pass user input to APIs that evaluate code. Offer a fixed set of operations, and map the user's choice to one of them, or use `PIL.ImageMath.lambda_eval` with a callable defined in your own code.

## Example

The following example passes the `function` request parameter to `ImageMath.eval`:

```python
from PIL import Image, ImageMath

def apply_function(request):
    function_str = request.POST.get("function")
    r, g, b = Image.open(request.FILES["file"]).convert("RGB").split()
    return ImageMath.eval(function_str, r=r, g=g, b=b)  # BAD
```

Using a constant expression, or one chosen from a fixed allowlist, is safe:

```python
ImageMath.eval("convert(r+g, '1')", r=r, g=g)  # GOOD
```

## References

- Pillow: [ImageMath module](https://pillow.readthedocs.io/en/stable/reference/ImageMath.html).
- NVD: [CVE-2023-50447](https://nvd.nist.gov/vuln/detail/CVE-2023-50447).
- Common Weakness Enumeration: [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Common Weakness Enumeration: [CWE-95](https://cwe.mitre.org/data/definitions/95.html).
- Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
