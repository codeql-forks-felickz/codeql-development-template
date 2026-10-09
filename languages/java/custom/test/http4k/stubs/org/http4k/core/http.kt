// Minimal stubs of the http4k-core API (https://github.com/http4k/http4k) with the
// same JVM signatures as the real library. Bodies are intentionally empty so that
// data flow only comes from the data extension models under test.
package org.http4k.core

import java.io.Closeable
import java.io.InputStream
import java.nio.ByteBuffer

interface Body : Closeable {
    val stream: InputStream
    val payload: ByteBuffer

    companion object {
        @JvmStatic
        @JvmName("create")
        operator fun invoke(body: String): Body = TODO()

        @JvmStatic
        @JvmName("create")
        operator fun invoke(body: InputStream, length: Long? = null): Body = TODO()
    }
}

interface HttpMessage : Closeable {
    val body: Body

    fun header(name: String): String?

    fun header(name: String, value: String?): HttpMessage

    fun headerValues(name: String): List<String?>

    fun bodyString(): String

    fun body(body: Body): HttpMessage

    fun body(body: String): HttpMessage
}

interface Request : HttpMessage {
    val uri: Uri

    fun query(name: String): String?

    fun queries(name: String): List<String?>

    override fun header(name: String, value: String?): Request

    override fun body(body: Body): Request

    override fun body(body: String): Request
}

interface Response : HttpMessage {
    override fun header(name: String, value: String?): Response

    fun replaceHeader(name: String, value: String?): Response

    override fun body(body: Body): Response

    override fun body(body: String): Response

    companion object {
        @JvmStatic
        @JvmName("create")
        operator fun invoke(status: Status): Response = TODO()
    }
}

class Status {
    companion object {
        val OK: Status = TODO()
        val FOUND: Status = TODO()
        val MOVED_PERMANENTLY: Status = TODO()
    }
}

class ContentType {
    companion object {
        val TEXT_PLAIN: ContentType = TODO()
    }
}
