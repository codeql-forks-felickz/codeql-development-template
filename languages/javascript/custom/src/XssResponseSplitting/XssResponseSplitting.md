# Stored cross-site scripting through Angular sanitizer bypass of HTTP response data

Angular automatically sanitizes values bound to `[innerHTML]` and `[style]` in component templates. `DomSanitizer.bypassSecurityTrustHtml` and `DomSanitizer.bypassSecurityTrustStyle` turn this protection off for a single value.

If the bypassed value comes from an HTTP response (for example, a product description loaded from the application's own REST API), anyone who can write that data on the server can store HTML or script that runs in the browser of every user who views it. This is stored cross-site scripting.

The stock `js/xss` query does not report this pattern. It does not treat HTTP response data as a source under the default threat model. It also does not recognize services obtained through Angular's `inject()` function (`inject(HttpClient)`, `inject(DomSanitizer)`, `inject(ProductService)`), because it resolves them only through type annotations.

## Recommendation

Do not call `bypassSecurityTrustHtml` or `bypassSecurityTrustStyle` on data received from a server. Bind the raw value to `[innerHTML]` and let Angular sanitize it. If the HTML must keep markup that Angular would remove, sanitize it first with a library such as DOMPurify before bypassing Angular's sanitizer.

## Example

The service loads products from the API, and the component marks each description as trusted HTML:

```ts
@Injectable({ providedIn: 'root' })
export class ProductService {
  private readonly http = inject(HttpClient)

  search (criteria: string) {
    return this.http.get(`/rest/products/search?q=${criteria}`).pipe(map((response: any) => response.data))
  }
}

export class SearchResultComponent {
  private readonly productService = inject(ProductService)
  private readonly sanitizer = inject(DomSanitizer)

  ngAfterViewInit () {
    this.productService.search('').subscribe((products) => {
      for (const product of products) {
        product.description = this.sanitizer.bypassSecurityTrustHtml(product.description) // BAD
      }
    })
  }
}
```

```html
<div [innerHTML]="product.description"></div>
```

Binding the value directly keeps Angular's sanitization in place:

```ts
this.productService.search('').subscribe((products) => {
  this.products = products // GOOD: Angular sanitizes [innerHTML]
})
```

## References

- Angular: [Security, sanitization and security contexts](https://angular.dev/best-practices/security#sanitization-and-security-contexts)
- Angular: [`DomSanitizer`](https://angular.dev/api/platform-browser/DomSanitizer)
- OWASP: [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
- Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html)
