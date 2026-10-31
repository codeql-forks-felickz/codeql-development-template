use ammonia::clean;
use iron::mime::Mime;
use iron::status;
use iron::{Chain, Iron, IronResult, Request, Response};

fn bad_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    // BAD: request path is formatted into markup and returned without encoding.
    let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
    Ok(Response::with((status::Ok, response))) // $ Alert[rust/xss-iron-response-modifier]=tuple
}

fn bad_body_only_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    // BAD: a body modifier on its own is also served without a `Content-Type`.
    Ok(Response::with(format!("<p>{:?}</p>", res))) // $ Alert[rust/xss]=body
}

fn good_sanitized_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
    // GOOD: sanitized by ammonia.
    let sanitized = clean(&*response);
    Ok(Response::with((status::Ok, sanitized)))
}

fn good_sanitized_body_only_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    // GOOD: sanitized by ammonia.
    Ok(Response::with(clean(&format!("<p>{:?}</p>", res))))
}

fn good_plain_text_handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
    // GOOD: an explicit `text/plain` content type is set.
    let plain: Mime = "text/plain".parse().unwrap();
    Ok(Response::with((status::Ok, plain, response)))
}

fn good_constant_handler(_req: &mut Request) -> IronResult<Response> {
    // GOOD: no user input in the body.
    Ok(Response::with((status::Ok, "<h1>Hello</h1>")))
}

mod prelude_style {
    use iron::prelude::*;
    use iron::status;

    pub fn handler(req: &mut Request) -> IronResult<Response> {
        let res = req.url.path();
        let response = format!("<h1>Assessing resource, {:?}!</h1>", res);
        // BAD: same as `bad_handler`, using the `iron::prelude` imports.
        Ok(Response::with((status::Ok, response))) // $ Alert[rust/xss-iron-response-modifier]=prelude
    }
}

fn main() {
    Iron::new(bad_handler).http("localhost:3000").unwrap(); // $ Source[rust/xss-iron-response-modifier]=tuple
    Iron::new(Chain::new(bad_body_only_handler)).http("localhost:3001").unwrap(); // $ Source[rust/xss]=body
    Iron::new(good_sanitized_handler).http("localhost:3002").unwrap();
    Iron::new(good_sanitized_body_only_handler).http("localhost:3003").unwrap();
    Iron::new(good_plain_text_handler).http("localhost:3004").unwrap();
    Iron::new(good_constant_handler).http("localhost:3005").unwrap();
    Iron::new(prelude_style::handler).http("localhost:3006").unwrap(); // $ Source[rust/xss-iron-response-modifier]=prelude
}
