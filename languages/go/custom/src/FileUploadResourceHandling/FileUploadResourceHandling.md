# HTTP server or client without resource limits
An HTTP server started with `http.ListenAndServe`, `http.ListenAndServeTLS`, `http.Serve` or `http.ServeTLS` uses a default `http.Server` whose `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout` and `IdleTimeout` are all zero. The same is true of an explicit `http.Server` that leaves these fields unset. A remote client can then open many connections and send request headers or bodies very slowly (a "Slowloris" attack), tying up goroutines and file descriptors until legitimate clients can no longer be served.

Similarly, the default HTTP client (`http.Get`, `http.Post`, `http.DefaultClient`, ...) has no timeout. Reading the whole body of a response from a non-constant URL with `io.ReadAll` lets the remote server stream indefinitely or send a very large body, exhausting memory and blocking the calling goroutine.


## Recommendation
Start servers through an explicit `http.Server` that sets at least `ReadHeaderTimeout` (or `ReadTimeout`), and preferably also `WriteTimeout` and `IdleTimeout`. Fetch remote content with an `http.Client` that has a `Timeout`, and bound the amount of data read, for example with `io.LimitReader`.


## Example
The following example starts a server with no timeouts, and reads an unbounded response body fetched with the default client:


```go
package main

import (
	"io"
	"net/http"
)

func fetch(target string) ([]byte, error) {
	// BAD: the default client has no timeout and the body size is unbounded.
	resp, err := http.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func main() {
	// BAD: the default server has no ReadHeaderTimeout, ReadTimeout or IdleTimeout.
	http.ListenAndServe(":8080", nil)
}

```
The following example configures server timeouts, uses a client with a timeout and limits the size of the response body that is read:


```go
package main

import (
	"io"
	"net/http"
	"time"
)

var client = &http.Client{Timeout: 10 * time.Second}

func fetch(target string) ([]byte, error) {
	// GOOD: the client has a timeout and the body is read with a size limit.
	resp, err := client.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func main() {
	// GOOD: the server bounds how long clients may take to send a request.
	srv := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	srv.ListenAndServe()
}

```

## References
* MITRE: [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html).
* Go documentation: [http.Server](https://pkg.go.dev/net/http#Server).
* Cloudflare: [The complete guide to Go net/http timeouts](https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/).
* Common Weakness Enumeration: [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
