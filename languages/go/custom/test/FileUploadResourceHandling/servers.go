package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

func listenDefault(addr string, h http.Handler) {
	http.ListenAndServe(addr, h) // $ Alert
}

func listenDefaultTLS(addr string) {
	http.ListenAndServeTLS(addr, "cert.pem", "key.pem", nil) // $ Alert
}

func serveDefault(l net.Listener) {
	http.Serve(l, nil) // $ Alert
}

func serveDefaultTLS(l net.Listener) {
	http.ServeTLS(l, nil, "cert.pem", "key.pem") // $ Alert
}

// govwa-style: an explicit server that only sets Addr and Handler.
func serverValueNoTimeouts(addr string, h http.Handler) {
	s := http.Server{ // $ Alert
		Addr:    addr,
		Handler: h,
	}
	s.ListenAndServe()
}

func serverPointerNoTimeouts(addr string, h http.Handler) {
	s := &http.Server{Addr: addr, Handler: h} // $ Alert
	s.ListenAndServeTLS("cert.pem", "key.pem")
}

func serverOnlyWriteTimeout(l net.Listener) {
	s := &http.Server{WriteTimeout: 10 * time.Second} // $ Alert
	s.Serve(l)
}

func newServer(addr string) *http.Server {
	return &http.Server{Addr: addr} // $ Alert
}

func serveFromConstructor() {
	newServer(":8080").ListenAndServe()
}

// Safe: header/read timeouts are configured.
func serverWithReadHeaderTimeout(addr string, h http.Handler) {
	s := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.ListenAndServe()
}

func serverWithReadTimeout(addr string) {
	s := http.Server{Addr: addr, ReadTimeout: 5 * time.Second}
	s.ListenAndServe()
}

func serverTimeoutAssignedLater(addr string) {
	s := &http.Server{Addr: addr}
	s.ReadHeaderTimeout = 5 * time.Second
	s.ListenAndServe()
}

func serverValueTimeoutAssignedLater(addr string) {
	s := http.Server{Addr: addr}
	s.ReadTimeout = 5 * time.Second
	s.ListenAndServe()
}

// Safe: never served, so it cannot be held open by clients.
func serverNeverServed(addr string) *tls.Config {
	s := &http.Server{Addr: addr}
	return s.TLSConfig
}

func main() {}
