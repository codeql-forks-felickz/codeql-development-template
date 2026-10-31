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
