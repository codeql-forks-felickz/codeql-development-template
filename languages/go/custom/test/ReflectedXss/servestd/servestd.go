package servestd

import (
	"fmt"
	"net/http"

	"example.com/reflectedxss/common"
)

func newHandler(v common.Route) http.HandlerFunc {
	for _, s := range v.Sinks {
		if s.Handler == nil {
			var err error
			s.Handler, err = common.GenericHandler(s)
			if err != nil {
				panic(err)
			}
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		for _, s := range v.Sinks {
			in := common.GetUserInput(r)
			data, mime, status := s.Handler(common.Unsafe, in, w)
			if len(data) == 0 {
				return
			}
			w.WriteHeader(status)
			if len(mime) == 0 {
				mime = "text/plain"
			}
			w.Header().Set("Content-Type", mime)
			fmt.Fprint(w, data) // $ Alert=bench
			return
		}
	}
}

// Setup registers all routes.
func Setup() {
	for _, r := range common.AllRoutes {
		http.HandleFunc(r.Base+"/", newHandler(r))
	}
	http.HandleFunc("/dynamic-content-type", func(w http.ResponseWriter, r *http.Request) {
		charset := r.FormValue("charset")
		w.Header().Set("Content-Type", "text/html; charset="+charset)
		fmt.Fprint(w, r.FormValue("input")) // $ Alert=htmlcontenttypeconcat
	})
}
