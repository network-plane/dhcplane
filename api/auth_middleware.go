// Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
// SPDX-License-Identifier: GPL-2.0-only

package api

import (
	"crypto/subtle"
	"net/http"
	"path"
	"strings"
)

func apiAuthMiddleware(tokenFunc func() string) func(http.Handler) http.Handler {
	if tokenFunc == nil {
		tokenFunc = func() string { return "" }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := strings.TrimSpace(tokenFunc())
			if tok == "" {
				next.ServeHTTP(w, r)
				return
			}
			if apiAuthExempt(r) {
				next.ServeHTTP(w, r)
				return
			}
			if !apiRequestAuthorized(r, tok) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("WWW-Authenticate", `Bearer realm="dhcplane"`)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized"}` + "\n"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func apiAuthExempt(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		return false
	}
	p := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
	return p == "/health" || p == "/ready" || p == "/stats/dashboard/ws"
}

func apiRequestAuthorized(r *http.Request, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return true
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) >= 7 && strings.EqualFold(auth[:7], "bearer ") {
		got := strings.TrimSpace(auth[7:])
		return subtleStringEqual(got, want)
	}
	if got := strings.TrimSpace(r.Header.Get("X-API-Token")); got != "" {
		return subtleStringEqual(got, want)
	}
	return false
}

func subtleStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
