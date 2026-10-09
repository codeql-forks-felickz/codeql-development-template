package org.http4k.lens

import org.http4k.core.HttpMessage

object Header {
    fun required(name: String): BiDiLens<HttpMessage, String> = TODO()
}
