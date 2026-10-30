import { Component, type AfterViewInit, inject } from '@angular/core'
import { DomSanitizer, type SafeHtml } from '@angular/platform-browser'
import { forkJoin } from 'rxjs'
import { ProductService } from '../Services/product.service'
import { QuantityService } from '../Services/quantity.service'

@Component({
  selector: 'app-search-result',
  templateUrl: './search-result.component.html'
})
export class SearchResultComponent implements AfterViewInit {
  private readonly productService = inject(ProductService)
  private readonly quantityService = inject(QuantityService)
  private readonly sanitizer = inject(DomSanitizer)

  public tableData!: any[]
  public trustedDescription?: SafeHtml

  ngAfterViewInit () {
    const products = this.productService.search('')
    const quantities = this.quantityService.getAll()
    forkJoin([quantities, products]).subscribe({
      next: ([quantities, products]) => {
        this.tableData = products
        this.trustProductDescription(products)
        for (const quantity of quantities) {
          this.trustedDescription = this.sanitizer.bypassSecurityTrustHtml(quantity.description) // $ Alert
        }
      },
      error: (err) => { console.log(err) }
    })
  }

  trustProductDescription (tableData: any[]) {
    for (let i = 0; i < tableData.length; i++) {
      tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description) // $ Alert
    }
  }
}
