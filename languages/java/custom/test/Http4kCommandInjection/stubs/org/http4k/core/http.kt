// Minimal stub of org.http4k:http4k-core:5.13.0.0 (org/http4k/core/http.kt).
package org.http4k.core

interface HttpMessage {
    fun header(name: String): String?

    fun headerValues(name: String): List<String?>

    fun bodyString(): String
}

interface Request : HttpMessage {
    fun query(name: String): String?

    fun queries(name: String): List<String?>
}
