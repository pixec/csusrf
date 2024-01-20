package csusrf

import "net/http"

var safeMethods = []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace}
