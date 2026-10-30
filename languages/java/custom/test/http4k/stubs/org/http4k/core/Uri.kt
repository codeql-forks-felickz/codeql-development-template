package org.http4k.core

class Uri {
    val path: String get() = TODO()
    val query: String get() = TODO()

    fun path(path: String): Uri = TODO()
    fun query(query: String): Uri = TODO()
    override fun toString(): String = TODO()

    companion object {
        @JvmStatic
        fun of(value: String): Uri = TODO()
    }
}

fun Uri.queryParametersEncoded(): Uri = TODO()
