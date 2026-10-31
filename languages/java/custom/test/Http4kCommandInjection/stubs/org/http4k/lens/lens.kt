// Minimal stub of org.http4k:http4k-core:5.13.0.0 (org/http4k/lens/extractInject.kt, lens.kt, query.kt, header.kt).
package org.http4k.lens

import org.http4k.core.HttpMessage
import org.http4k.core.Request

interface LensExtractor<in IN, out OUT> : (IN) -> OUT {
    override operator fun invoke(target: IN): OUT

    fun extract(target: IN): OUT

    operator fun <R : IN> get(target: R): OUT
}

open class Lens<in IN : Any, out FINAL> : LensExtractor<IN, FINAL> {
    override operator fun invoke(target: IN): FINAL = TODO()

    override fun extract(target: IN): FINAL = TODO()

    override operator fun <R : IN> get(target: R): FINAL = TODO()
}

object Query {
    fun required(name: String): Lens<Request, String> = TODO()

    fun defaulted(name: String, default: String): Lens<Request, String> = TODO()
}

object Header {
    fun required(name: String): Lens<HttpMessage, String> = TODO()
}
