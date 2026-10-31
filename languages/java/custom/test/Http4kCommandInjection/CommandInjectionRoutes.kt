package com.example.routes

import org.http4k.core.Request
import org.http4k.core.body.form
import org.http4k.lens.Header
import org.http4k.lens.Query
import org.http4k.routing.path

// http4k request sources reaching a shell command line.

fun httpMessageHeaderShell(request: Request) {
    val command = request.header("X-Command") ?: "echo hello" // $ Source
    Runtime.getRuntime().exec("sh -c $command") // $ Alert
}

fun httpMessageHeaderValuesShell(request: Request) {
    val command = request.headerValues("X-Command").first() ?: "echo hello" // $ Source
    Runtime.getRuntime().exec("sh -c $command") // $ Alert
}

fun httpMessageBodyStringShell(request: Request) {
    Runtime.getRuntime().exec(request.bodyString()) // $ Alert
}

fun requestQueryShell(request: Request) {
    val command = request.query("cmd") ?: "echo hello" // $ Source
    Runtime.getRuntime().exec("sh -c $command") // $ Alert
}

fun requestQueriesShell(request: Request) {
    val command = request.queries("cmd").first() ?: "echo hello" // $ Source
    Runtime.getRuntime().exec("sh -c $command") // $ Alert
}

fun routingPathShell(request: Request) {
    val command = request.path("cmd") ?: "echo hello" // $ Source
    Runtime.getRuntime().exec(arrayOf("sh", "-c", command)) // $ Alert
}

fun formFieldShell(request: Request) {
    val command = request.form("cmd") ?: "echo hello" // $ Source
    Runtime.getRuntime().exec(arrayOf("sh", "-c", command)) // $ Alert
}

fun lensInvokeShell(request: Request) {
    val cmdLens = Query.defaulted("cmd", "echo hello")
    val command = cmdLens(request) // $ Source
    Runtime.getRuntime().exec(arrayOf("sh", "-c", command)) // $ Alert
}

fun lensGetShell(request: Request) {
    val cmdLens = Query.required("cmd")
    val command = cmdLens.get(request) // $ Source
    Runtime.getRuntime().exec(arrayOf("sh", "-c", command)) // $ Alert
}

fun lensExtractShell(request: Request) {
    val command = Header.required("X-Command").extract(request) // $ Source
    Runtime.getRuntime().exec(arrayOf("sh", "-c", command)) // $ Alert
}

// Reductions of the linked AI scan findings: the request value is passed as a later
// element of an argument array whose program is a fixed, non-shell binary (`ping`,
// `nslookup`). `java/command-line-injection` deliberately treats such arguments as safe
// (`isSafeCommandArgument`), because no shell interprets them. The remaining risk is a
// CWE-918 style network probe, which this query does not model.

fun lensGetPing(request: Request) {
    val host = Query.required("host").get(request)
    Runtime.getRuntime().exec(arrayOf("ping", "-c", "1", host))
}

fun lensInvokePing(request: Request) {
    val host = Query.defaulted("host", "localhost")(request)
    Runtime.getRuntime().exec(arrayOf("ping", "-c", "1", host))
}

fun httpMessageHeaderNslookup(request: Request) {
    val target = request.header("X-Target") ?: "localhost"
    Runtime.getRuntime().exec(arrayOf("nslookup", target))
}

// Safe: request data is read but never reaches the command.

fun constantCommand(request: Request) {
    request.header("X-Target")
    Runtime.getRuntime().exec(arrayOf("ping", "-c", "1", "localhost"))
}
