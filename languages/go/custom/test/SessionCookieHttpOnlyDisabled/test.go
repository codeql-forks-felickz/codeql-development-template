package main

import (
	"net/http"

	ginsessions "github.com/gin-contrib/sessions"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
)

var store = sessions.NewCookieStore([]byte("key"))

type config struct {
	HttpOnly bool
}

const cookieHttpOnly = false

// Reduced from a session helper that disables HttpOnly on the authenticated session cookie.
func setSessionBad(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "app")
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: false, // $ Alert
	}
	session.Values["authenticated"] = true
	session.Save(r, w)
}

func deleteSessionBad(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "app")
	session.Options = &sessions.Options{MaxAge: -1, HttpOnly: false} // $ Alert
	session.Save(r, w)
}

func storeFieldWriteBad() {
	store.Options.HttpOnly = false // $ Alert
}

func namedConstantBad(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "app")
	session.Options = &sessions.Options{Path: "/", HttpOnly: cookieHttpOnly} // $ Alert
	session.Save(r, w)
}

func localVariableBad(w http.ResponseWriter, r *http.Request) {
	httpOnly := false
	opts := sessions.Options{Path: "/"}
	opts.HttpOnly = httpOnly // $ Alert
	session, _ := store.Get(r, "app")
	session.Options = &opts
	session.Save(r, w)
}

func newCookieBad(w http.ResponseWriter) {
	http.SetCookie(w, sessions.NewCookie("app", "v", &sessions.Options{HttpOnly: false, Secure: true})) // $ Alert
}

func ginContribBad(session ginsessions.Session) {
	session.Options(ginsessions.Options{Path: "/", MaxAge: 3600, HttpOnly: false}) // $ Alert
	session.Save()
}

func ginContribStoreBad(s ginsessions.Store) {
	s.Options(ginsessions.Options{HttpOnly: false, Secure: true}) // $ Alert
}

func authorizationCookiesBad(w http.ResponseWriter) {
	writeCookie(w, "Level", "high")
	writeCookie(w, "Uid", "123")
}

func writeCookie(w http.ResponseWriter, name, value string) {
	cookie := http.Cookie{Name: name, Value: value, Secure: true}
	http.SetCookie(w, &cookie) // $ Alert
}

func echoSessionCookiesBad(c echo.Context) {
	cookie := new(http.Cookie)
	cookie.Name = "sessionIDa5"
	cookie.Value = "jwt"
	cookie.Secure = true
	c.SetCookie(cookie) // $ Alert

	cookie = new(http.Cookie)
	cookie.Name = "sessionIDsnake"
	cookie.Value = "jwt"
	cookie.Secure = true
	c.SetCookie(cookie) // $ Alert
}

func nonSensitiveCookieGood(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark", Secure: true})
}

func httpOnlyCookieGood(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "sessionToken", Value: "jwt", HttpOnly: true, Secure: true})
}

func explicitFalseCookieBad(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "sessionToken", Value: "jwt", HttpOnly: false, Secure: true}) // $ Alert
}

func echoHttpOnlyCookieGood(c echo.Context) {
	cookie := &http.Cookie{Name: "sessionToken", Value: "jwt", HttpOnly: true, Secure: true}
	c.SetCookie(cookie)
}

func setSessionGood(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "app")
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
	}
	session.Save(r, w)
}

func storeFieldWriteGood() {
	store.Options.HttpOnly = true
}

func ginContribGood(session ginsessions.Session) {
	session.Options(ginsessions.Options{Path: "/", HttpOnly: true})
}

// Not reported: the value is not a constant `false` (it comes from configuration).
func fromConfig(w http.ResponseWriter, r *http.Request, cfg config) {
	session, _ := store.Get(r, "app")
	session.Options = &sessions.Options{Path: "/", HttpOnly: cfg.HttpOnly}
	session.Save(r, w)
}

// Not reported: `Secure` is disabled, but `HttpOnly` is not configured explicitly.
func secureDisabledOnly(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "app")
	session.Options = &sessions.Options{Path: "/", Secure: false}
	session.Save(r, w)
}

// Not reported: an unrelated struct with an `HttpOnly` field.
type otherOptions struct {
	HttpOnly bool
}

func unrelatedStruct() otherOptions {
	return otherOptions{HttpOnly: false}
}

func main() {}
