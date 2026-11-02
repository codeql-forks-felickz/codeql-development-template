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

func serverLiteralZeroTimeout() {
	s := &http.Server{ReadTimeout: 0} // $ Alert
	s.ListenAndServe()
}

func serverLiteralZeroTimeoutExpression() {
	s := &http.Server{ReadTimeout: 0 * time.Second} // $ Alert
	s.ListenAndServe()
}

func serverLiteralZeroTimeoutConversion() {
	s := &http.Server{ReadHeaderTimeout: time.Duration(0)} // $ Alert
	s.ListenAndServe()
}

func serverLiteralNegativeTimeout() {
	s := &http.Server{ReadTimeout: -time.Second} // $ Alert
	s.ListenAndServe()
}

func serverAssignedZeroTimeout() {
	s := &http.Server{Addr: ":8080"} // $ Alert
	s.ReadTimeout = 0
	s.ListenAndServe()
}

func serverAssignedZeroTimeoutExpression() {
	s := &http.Server{Addr: ":8080"} // $ Alert
	s.ReadTimeout = 0 * time.Second
	s.ListenAndServe()
}

func serverAssignedZeroTimeoutConversion() {
	s := &http.Server{Addr: ":8080"} // $ Alert
	s.ReadHeaderTimeout = time.Duration(0)
	s.ListenAndServe()
}

func serverAssignedNegativeTimeout() {
	s := &http.Server{Addr: ":8080"} // $ Alert
	s.ReadTimeout = -time.Second
	s.ListenAndServe()
}

func serverLiteralDynamicTimeout(timeout time.Duration) {
	s := &http.Server{ReadTimeout: timeout}
	s.ListenAndServe()
}

func serverAssignedDynamicTimeout(timeout time.Duration) {
	s := &http.Server{Addr: ":8080"}
	s.ReadTimeout = timeout
	s.ListenAndServe()
}

// Safe: never served, so it cannot be held open by clients.
func serverNeverServed(addr string) *tls.Config {
	s := &http.Server{Addr: addr}
	return s.TLSConfig
}

func main() {}
