import { Injectable } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { map } from 'rxjs/operators'

@Injectable({ providedIn: 'root' })
export class QuantityService {
  constructor (private readonly http: HttpClient) {}

  getAll () {
    return this.http.get('/api/Quantitys/').pipe(map((response: any) => response.data)) // $ Source
  }
}
