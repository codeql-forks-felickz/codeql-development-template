import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { catchError, map } from 'rxjs/operators'

@Injectable({ providedIn: 'root' })
export class ProductService {
  private readonly http = inject(HttpClient)
  private readonly host = '/api/Products'

  search (criteria: string) {
    return this.http.get(`/rest/products/search?q=${criteria}`).pipe(map((response: any) => response.data), catchError((err) => { throw err })) // $ Source
  }

  get (id: number) {
    return this.http.get(`${this.host}/${id}`).pipe(map((response: any) => response.data)) // $ Source
  }
}
