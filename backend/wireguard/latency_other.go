//go:build !linux

package wireguard

import "net/http"

func latencyHTTPTransport(_ string) *http.Transport {
	return http.DefaultTransport.(*http.Transport).Clone()
}
