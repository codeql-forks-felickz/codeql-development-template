use warp::Filter;

// BAD: a URL path parameter is used as the host of an outbound request.
pub async fn bad_path_param() {
    let routes = warp::path::param().then(|tainted_param: String| async move {
        let response = reqwest::Client::new()
            .post(format!("https://{}", tainted_param)) // $ Alert
            .form(&[("one", "1")])
            .send()
            .await
            .expect("send");

        format!("{}", response.status())
    }); // $ Source (the source is the `then` closure, reported at its last line)

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

// GOOD: the path parameter is only used in the path of a request to a fixed host.
pub async fn good_fixed_host() {
    let routes = warp::path::param().then(|tainted_param: String| async move {
        let response = reqwest::Client::new()
            .post(format!("https://my.app/{}", tainted_param))
            .send()
            .await
            .expect("send");

        format!("{}", response.status())
    });

    warp::serve(routes).run(([127, 0, 0, 1], 3031)).await;
}
