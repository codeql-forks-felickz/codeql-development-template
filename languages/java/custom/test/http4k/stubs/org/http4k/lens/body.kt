package org.http4k.lens

import org.http4k.core.Body
import org.http4k.core.ContentType

class BiDiBodyLensSpec<OUT> {
    fun toLens(): BiDiBodyLens<OUT> = TODO()
}

fun Body.Companion.string(contentType: ContentType): BiDiBodyLensSpec<String> = TODO()
