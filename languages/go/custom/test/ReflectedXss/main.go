package main

import (
	"net/http"

	"example.com/reflectedxss/filters"
	"example.com/reflectedxss/jsonapi"
	"example.com/reflectedxss/servestd"
	"example.com/reflectedxss/xss"
)

func main() {
	xss.RegisterRoutes()
	servestd.Setup()
	jsonapi.Setup()
	filters.Setup()
	http.ListenAndServe(":8080", nil)
}
