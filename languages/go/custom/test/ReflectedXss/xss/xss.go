package xss

import (
	"net/url"

	"example.com/reflectedxss/common"
)

// RegisterRoutes registers a sink whose unsafe mode returns the payload
// verbatim as `text/html`.
func RegisterRoutes() {
	sinks := []*common.Sink{
		{
			Name:     "reflectedXss",
			Sanitize: url.PathEscape,
			VulnerableFnWrapper: func(_ interface{}, payload string) (data string, raw bool, err error) {
				return payload, true, nil
			},
			RawMime: "text/html",
		},
	}
	common.Register(common.Route{Base: "xss", Sinks: sinks})
}
