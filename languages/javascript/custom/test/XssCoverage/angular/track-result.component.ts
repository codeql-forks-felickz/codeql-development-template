import { ActivatedRoute } from '@angular/router'
import { HttpClient } from '@angular/common/http'
import { Component, inject } from '@angular/core'
import { DomSanitizer } from '@angular/platform-browser'

// Out of scope: the order id is reflected by the backend API. Treating every API response
// as attacker-controlled would be far too noisy, so this remains a known false negative.
@Component({ selector: 'app-track-result', template: '<span [innerHTML]="orderNo"></span>' })
export class TrackResultComponent {
  private readonly route = inject(ActivatedRoute)
  private readonly http = inject(HttpClient)
  private readonly sanitizer = inject(DomSanitizer)
  public orderNo: any

  ngOnInit () {
    const orderId = this.route.snapshot.queryParams.id
    this.http.get<any>('/rest/track-order/' + orderId).subscribe((results) => {
      this.orderNo = this.sanitizer.bypassSecurityTrustHtml(`<code>${results.data[0].orderId}</code>`) // $ MISSING: Alert[js/xss]
    })
  }
}
