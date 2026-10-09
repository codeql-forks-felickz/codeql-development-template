package com.example.routes

import org.http4k.core.Body
import org.http4k.core.ContentType
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status
import org.http4k.core.body.form
import org.http4k.core.cookie.cookie
import org.http4k.core.queryParametersEncoded
import org.http4k.lens.Header
import org.http4k.lens.Query
import org.http4k.lens.string
import org.http4k.routing.path
import java.io.File
import java.sql.DriverManager

// CWE-089: SQL injection (java/sql-injection)

fun sqlInjectionLensGet(request: Request): Response {
    val userLens = Query.required("id")
    val userId = userLens[request] // $ Source[java/sql-injection]
    val statement = DriverManager.getConnection("jdbc:h2:mem:testdb").createStatement()
    statement.executeQuery("SELECT * FROM users WHERE id = $userId") // $ Alert[java/sql-injection]
    return Response(Status.OK).body("done")
}

fun sqlInjectionLensInvoke(request: Request): Response {
    val userId = Query.required("id")(request) // $ Source[java/sql-injection]
    val statement = DriverManager.getConnection("jdbc:h2:mem:testdb").createStatement()
    statement.executeQuery("SELECT * FROM users WHERE id = $userId") // $ Alert[java/sql-injection]
    return Response(Status.OK)
}

fun sqlInjectionLensExtract(request: Request): Response {
    val userId = Header.required("X-User-ID").extract(request) // $ Source[java/sql-injection]
    val statement = DriverManager.getConnection("jdbc:h2:mem:testdb").createStatement()
    statement.executeQuery("SELECT * FROM users WHERE id = $userId") // $ Alert[java/sql-injection]
    return Response(Status.OK)
}

fun sqlInjectionRequestHeader(request: Request): Response {
    val userId = request.header("X-User-ID") ?: "1" // $ Source[java/sql-injection]
    val statement = DriverManager.getConnection("jdbc:h2:mem:testdb").createStatement()
    statement.executeQuery("SELECT * FROM accounts WHERE id = $userId") // $ Alert[java/sql-injection]
    return Response(Status.OK)
}

fun sqlInjectionRequestHeaderValues(request: Request): Response {
    val userId = request.headerValues("X-User-ID")[0] // $ Source[java/sql-injection]
    val statement = DriverManager.getConnection("jdbc:h2:mem:testdb").createStatement()
    statement.executeQuery("SELECT * FROM accounts WHERE id = $userId") // $ Alert[java/sql-injection]
    return Response(Status.OK)
}

fun sqlInjectionRequestQueries(request: Request): Response {
    val userId = request.queries("id")[0] // $ Source[java/sql-injection]
    val statement = DriverManager.getConnection("jdbc:h2:mem:testdb").createStatement()
    statement.executeQuery("SELECT * FROM accounts WHERE id = $userId") // $ Alert[java/sql-injection]
    return Response(Status.OK)
}

fun sqlInjectionUriQuery(request: Request): Response {
    val userId = request.uri.query.substringAfter("id=") // $ Source[java/sql-injection]
    val statement = DriverManager.getConnection("jdbc:h2:mem:testdb").createStatement()
    statement.executeQuery("SELECT * FROM accounts WHERE id = $userId") // $ Alert[java/sql-injection]
    return Response(Status.OK)
}

fun sqlInjectionUriQueryParametersEncoded(request: Request): Response {
    val userId = request.uri.queryParametersEncoded().query // $ Source[java/sql-injection]
    val statement = DriverManager.getConnection("jdbc:h2:mem:testdb").createStatement()
    statement.executeQuery("SELECT * FROM accounts WHERE id = $userId") // $ Alert[java/sql-injection]
    return Response(Status.OK)
}

fun sqlInjectionForm(request: Request): Response {
    val userId = request.form("id") // $ Source[java/sql-injection]
    val statement = DriverManager.getConnection("jdbc:h2:mem:testdb").createStatement()
    statement.executeQuery("SELECT * FROM accounts WHERE id = $userId") // $ Alert[java/sql-injection]
    return Response(Status.OK)
}

fun sqlInjectionCookie(request: Request): Response {
    val userId = request.cookie("session")?.value // $ Source[java/sql-injection]
    val statement = DriverManager.getConnection("jdbc:h2:mem:testdb").createStatement()
    statement.executeQuery("SELECT * FROM accounts WHERE id = $userId") // $ Alert[java/sql-injection]
    return Response(Status.OK)
}

fun sqlInjectionPathParameter(request: Request): Response {
    val userId = request.path("id") // $ Source[java/sql-injection]
    val statement = DriverManager.getConnection("jdbc:h2:mem:testdb").createStatement()
    statement.executeQuery("SELECT * FROM accounts WHERE id = $userId") // $ Alert[java/sql-injection]
    return Response(Status.OK)
}

fun sqlInjectionSafeConstant(request: Request): Response {
    val userId = "42"
    val statement = DriverManager.getConnection("jdbc:h2:mem:testdb").createStatement()
    statement.executeQuery("SELECT * FROM accounts WHERE id = $userId")
    return Response(Status.OK)
}

// CWE-079: Cross-site scripting (java/xss)

fun xssQuery(request: Request): Response {
    val data = request.query("data") ?: "" // $ Source[java/xss]
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>Hello $data</body></html>") // $ Alert[java/xss]
}

fun xssBodyString(request: Request): Response {
    val data = request.bodyString() // $ Source[java/xss]
    return Response(Status.OK).body("<p>$data</p>") // $ Alert[java/xss]
}

fun xssBodyStream(request: Request): Response {
    val data = request.body.stream.bufferedReader().readText() // $ Source[java/xss]
    return Response(Status.OK).body("<p>$data</p>") // $ Alert[java/xss]
}

fun xssBodyPayload(request: Request): Response {
    val data = String(request.body.payload.array()) // $ Source[java/xss]
    return Response(Status.OK).body("<p>$data</p>") // $ Alert[java/xss]
}

fun xssBodyLens(request: Request): Response {
    val data = Body.string(ContentType.TEXT_PLAIN).toLens()(request) // $ Source[java/xss]
    return Response(Status.OK).body(Body("<p>$data</p>")) // $ Alert[java/xss]
}

fun xssSafeConstant(request: Request): Response {
    val data = "world"
    return Response(Status.OK).body("<p>Hello $data</p>")
}

// CWE-601: URL redirection (java/unvalidated-url-redirection)
// CWE-113: HTTP response splitting (java/http-response-splitting)

fun redirectUriQuery(request: Request): Response {
    val target = request.uri.query.substringAfter("target=") // $ Source[java/unvalidated-url-redirection] Source[java/http-response-splitting]
    return Response(Status.MOVED_PERMANENTLY).header("Location", target) // $ Alert[java/unvalidated-url-redirection] Alert[java/http-response-splitting]
}

fun redirectReplaceHeader(request: Request): Response {
    val target = request.query("next") ?: "/" // $ Source[java/unvalidated-url-redirection] Source[java/http-response-splitting]
    return Response(Status.FOUND).replaceHeader("Location", target) // $ Alert[java/unvalidated-url-redirection] Alert[java/http-response-splitting]
}

fun redirectSafeConstant(request: Request): Response {
    return Response(Status.FOUND).header("Location", "/home")
}

fun headerInjectionBodyStream(request: Request): Response {
    val value = request.body.stream.readBytes().decodeToString() // $ Source[java/unvalidated-url-redirection] Source[java/http-response-splitting]
    return Response(Status.OK).header("X-Custom", value) // $ Alert[java/unvalidated-url-redirection] Alert[java/http-response-splitting]
}

fun headerSafeConstant(request: Request): Response {
    val value = "static"
    return Response(Status.OK).header("X-Custom", value)
}

// CWE-022: Path injection (java/path-injection)

fun pathInjectionBodyStream(request: Request): Response {
    val name = request.body.stream.bufferedReader().readText() // $ Source[java/path-injection]
    return Response(Status.OK).body(File("/data/$name").readText()) // $ Alert[java/path-injection]
}

fun pathInjectionUriPath(request: Request): Response {
    val name = request.uri.path // $ Source[java/path-injection]
    return Response(Status.OK).body(File("/data/$name").readText()) // $ Alert[java/path-injection]
}

fun pathSafeConstant(request: Request): Response {
    val name = "index.html"
    return Response(Status.OK).body(File("/data/$name").readText())
}
