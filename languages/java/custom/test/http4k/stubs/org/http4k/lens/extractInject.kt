package org.http4k.lens

interface LensExtractor<in IN, out OUT> : (IN) -> OUT {
    override operator fun invoke(target: IN): OUT

    fun extract(target: IN): OUT

    operator fun <R : IN> get(target: R): OUT
}
