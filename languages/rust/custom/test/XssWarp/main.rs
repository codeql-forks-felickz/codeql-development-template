use warp::Filter;

#[tokio::main]
async fn main() {
    // BAD: tainted path parameter is returned as an HTML reply (already modeled by `codeql/rust-all`).
    let html = warp::path("html").and(warp::path::param()).map(|name: String| {
        warp::reply::html(format!("<h1>Hello, {}!</h1>", name)) // $ Alert[rust/xss]=html
    }); // $ Source[rust/xss]=html

    // GOOD: warp serves a `String` reply as `text/plain; charset=utf-8`, which browsers do not
    // sniff as HTML, so it is intentionally not modeled as an `html-injection` sink.
    let text = warp::path("text").and(warp::path::param()).map(|name: String| {
        format!("<h1>Hello, {}!</h1>", name)
    });

    // GOOD: same as above, using `then` and debug formatting.
    let debug = warp::path("debug").and(warp::path::param()).then(|name: String| async move {
        format!("Got {:?}", name)
    });

    warp::serve(html.or(text).or(debug)).run(([127, 0, 0, 1], 3030)).await;
}
