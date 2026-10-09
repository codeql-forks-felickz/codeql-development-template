package org.http4k.core

class Uri {
    val path: String get() = TODO()
    val query: String get() = TODO()

    companion object {
        @JvmStatic
        fun of(value: String): Uri = TODO()
    }
}

fun Uri.queryParametersEncoded(): Uri = TODO()
