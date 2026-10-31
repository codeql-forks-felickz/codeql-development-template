package main

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// go-test-bench-style: fetch a caller-chosen URL with the default client and
// read the whole body.
func fetchUnbounded(payload string) string {
	resp, err := http.Get(payload)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	bdy, _ := ioutil.ReadAll(resp.Body) // $ Alert
	return string(bdy)
}

func postUnbounded(target string) []byte {
	resp, _ := http.Post(target, "text/plain", nil)
	b, _ := io.ReadAll(resp.Body) // $ Alert
	return b
}

func postFormUnbounded(target string) []byte {
	resp, _ := http.PostForm(target, url.Values{})
	b, _ := io.ReadAll(resp.Body) // $ Alert
	return b
}

func defaultClientUnbounded(target string) []byte {
	resp, _ := http.DefaultClient.Get(target)
	body := resp.Body
	b, _ := io.ReadAll(body) // $ Alert
	return b
}

// Safe: the body is bounded with io.LimitReader.
func fetchLimited(payload string) []byte {
	resp, _ := http.Get(payload)
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return b
}

// Safe: a client with an explicit timeout is used.
func fetchWithTimeoutClient(payload string) []byte {
	c := &http.Client{Timeout: 10 * time.Second}
	resp, _ := c.Get(payload)
	b, _ := io.ReadAll(resp.Body)
	return b
}

// Safe: a constant URL is a trusted endpoint.
func fetchConstant() []byte {
	resp, _ := http.Get("https://example.com/health")
	b, _ := io.ReadAll(resp.Body)
	return b
}
