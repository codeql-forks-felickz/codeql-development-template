package org.http4k.lens

import org.http4k.core.HttpMessage

open class Lens<in IN : Any, out FINAL> : LensExtractor<IN, FINAL> {
    override operator fun invoke(target: IN): FINAL = TODO()

    override fun extract(target: IN): FINAL = TODO()

    override operator fun <R : IN> get(target: R): FINAL = TODO()
}

open class BiDiLens<in IN : Any, FINAL> : Lens<IN, FINAL>()

open class BodyLens<out FINAL> : LensExtractor<HttpMessage, FINAL> {
    override operator fun invoke(target: HttpMessage): FINAL = TODO()

    override fun extract(target: HttpMessage): FINAL = TODO()

    override operator fun <R : HttpMessage> get(target: R): FINAL = TODO()
}

open class BiDiBodyLens<FINAL> : BodyLens<FINAL>()
