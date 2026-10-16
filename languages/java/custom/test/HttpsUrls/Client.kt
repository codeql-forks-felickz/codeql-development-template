package com.example

import retrofit2.Retrofit

interface Client {
    companion object {
        fun create(hostname: String, port: String): Client {
            val baseUrl: String = "http://${hostname}:${port}" // $ Source
            val retrofit = Retrofit.Builder()
                .baseUrl(baseUrl) // $ Alert
                .build()
            return retrofit.create(Client::class.java)
        }

        fun createConcat(hostname: String): Client {
            val retrofit = Retrofit.Builder()
                .baseUrl("http://" + hostname) // $ Alert
                .build()
            return retrofit.create(Client::class.java)
        }

        fun createSecure(hostname: String, port: String): Client {
            val retrofit = Retrofit.Builder()
                .baseUrl("https://${hostname}:${port}")
                .build()
            return retrofit.create(Client::class.java)
        }
    }
}

object PreferenceHelper {
    fun getString(key: String, default: String): String = default
}

object Client2 {
    fun create(): Client {
        val hostname: String = PreferenceHelper.getString("ip_address", "127.0.0.1")
        val port: String = PreferenceHelper.getString("port", "8080")
        val baseUrl: String = "http://${hostname}:${port}" // $ Source
        val retrofit = Retrofit.Builder()
            .baseUrl(baseUrl) // $ Alert
            .build()
        return retrofit.create(Client::class.java)
    }
}
