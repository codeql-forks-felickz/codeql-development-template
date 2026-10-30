import { Component, type OnInit, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { DomSanitizer, type SafeHtml } from '@angular/platform-browser'
import DOMPurify from 'dompurify'
import { ProductService } from '../Services/product.service'

class NotASanitizer {
  bypassSecurityTrustHtml (value: string): string { return value }
}

@Component({
  selector: 'app-safe-product',
  templateUrl: './safe-product.component.html'
})
export class SafeProductComponent implements OnInit {
  private readonly productService = inject(ProductService)
  private readonly http = inject(HttpClient)
  private readonly sanitizer = inject(DomSanitizer)
  private readonly other = inject(NotASanitizer)

  // Bound to [innerHTML] without bypassing Angular's built-in sanitization: safe.
  public plainDescription = ''
  public banner?: SafeHtml
  public purified?: SafeHtml
  public other_?: string

  ngOnInit (): void {
    this.productService.get(1).subscribe((product: any) => {
      this.plainDescription = product.description
      this.purified = this.sanitizer.bypassSecurityTrustHtml(DOMPurify.sanitize(product.description))
      this.other_ = this.other.bypassSecurityTrustHtml(product.description)
    })
    this.http.get('/api/Products/1').subscribe((product: any) => {
      this.plainDescription = product.description
    })
    this.banner = this.sanitizer.bypassSecurityTrustHtml('<b>Welcome</b>')
  }
}
