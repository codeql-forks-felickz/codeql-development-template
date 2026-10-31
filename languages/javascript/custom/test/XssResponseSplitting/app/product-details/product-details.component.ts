import { Component, type OnInit } from '@angular/core'
import { DomSanitizer, type SafeHtml } from '@angular/platform-browser'
import { ProductService } from '../Services/product.service'

@Component({
  selector: 'app-product-details',
  templateUrl: './product-details.component.html'
})
export class ProductDetailsComponent implements OnInit {
  public description?: SafeHtml
  public style?: SafeHtml

  constructor (private readonly productService: ProductService, private readonly sanitizer: DomSanitizer) {}

  ngOnInit (): void {
    this.productService.get(1).subscribe((product: any) => {
      this.description = this.sanitizer.bypassSecurityTrustHtml(product.description) // $ Alert
      this.style = this.sanitizer.bypassSecurityTrustStyle(product.style) // $ Alert
    })
  }
}
