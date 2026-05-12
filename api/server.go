// Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
// SPDX-License-Identifier: GPL-2.0-only

package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"dhcplane/ratelimit"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var (
	apiServerMu sync.Mutex
	apiServer   *http.Server
)

// BuildInfo returns version and runtime metadata for JSON APIs.
func BuildInfo(appVersion string) map[string]string {
	return map[string]string{
		"version":    appVersion,
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

// RegisterDHCPRoutes wires read-only DHCP/lease REST handlers (expects auth middleware applied on parent router if needed).
func RegisterDHCPRoutes(router chi.Router, deps *Deps) {
	if router == nil || deps == nil {
		return
	}
	d := deps
	router.Get("/health", healthHandler)
	router.Get("/ready", func(w http.ResponseWriter, r *http.Request) { readyHandler(w, r, d) })
	router.Get("/version", func(w http.ResponseWriter, r *http.Request) { versionHandler(w, r, d) })
	router.Get("/dhcp/leases", func(w http.ResponseWriter, r *http.Request) { leasesHandler(w, r, d) })
	router.Get("/dhcp/reservations", func(w http.ResponseWriter, r *http.Request) { reservationsHandler(w, r, d) })
	router.Get("/dhcp/stats", func(w http.ResponseWriter, r *http.Request) { statsHandler(w, r, d) })
	router.Get("/stats/dashboard", func(w http.ResponseWriter, r *http.Request) { dashboardPageHandler(w, r, d) })
	router.Get("/stats/dashboard/data", func(w http.ResponseWriter, r *http.Request) { dashboardDataHandler(w, r, d) })
	router.Get("/stats/dashboard/ws", func(w http.ResponseWriter, r *http.Request) { dashboardWebSocketHandler(w, r, d) })
}

func buildRouter(deps *Deps, opts *ListenOptions) http.Handler {
	if opts == nil {
		opts = &ListenOptions{}
	}
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.Logger)
	var lim *ratelimit.PerIP
	if opts.RateLimitRPS > 0 {
		burst := opts.RateLimitBurst
		if burst <= 0 {
			burst = 20
		}
		lim = ratelimit.NewPerIP(opts.RateLimitRPS, burst)
	}
	if lim != nil {
		r.Use(rateLimitMiddleware(lim))
	}
	var tok func() string
	if deps != nil && deps.AuthToken != nil {
		tok = deps.AuthToken
	}
	r.Use(apiAuthMiddleware(tok))
	RegisterDHCPRoutes(r, deps)
	return r
}

// Start runs the REST API in a background goroutine. port must be non-empty (e.g. "8080").
func Start(port string, opts *ListenOptions, deps *Deps, log *slog.Logger) {
	if deps == nil {
		logAPIWarn(log, "api.Start: nil deps")
		return
	}
	port = strings.TrimSpace(port)
	if port == "" {
		logAPIWarn(log, "api.Start: empty port")
		return
	}
	apiServerMu.Lock()
	if apiServer != nil {
		apiServerMu.Unlock()
		if log != nil {
			log.Info("API server already running; skipping start")
		}
		return
	}
	if opts == nil {
		opts = &ListenOptions{}
	}
	bindIP := strings.TrimSpace(opts.BindIP)
	addr := ":" + port
	if bindIP != "" {
		addr = net.JoinHostPort(bindIP, port)
	}
	if log != nil {
		log.Info("API server starting", "addr", addr, "tls", opts.TLSCertFile != "" && opts.TLSKeyFile != "")
	}
	h := buildRouter(deps, opts)
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	apiServer = srv
	apiServerMu.Unlock()

	go func() {
		defer func() {
			apiServerMu.Lock()
			if apiServer == srv {
				apiServer = nil
			}
			apiServerMu.Unlock()
		}()
		var err error
		if strings.TrimSpace(opts.TLSCertFile) != "" && strings.TrimSpace(opts.TLSKeyFile) != "" {
			err = srv.ListenAndServeTLS(opts.TLSCertFile, opts.TLSKeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logAPIError(log, "API server stopped with error", "error", err)
		}
	}()
}

// Stop shuts down the API server. No-op if not running.
func Stop(log *slog.Logger) {
	apiServerMu.Lock()
	srv := apiServer
	apiServer = nil
	apiServerMu.Unlock()
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logAPIWarn(log, "API Shutdown", "error", err)
	}
}

// Running reports whether the HTTP API listener is active.
func Running() bool {
	apiServerMu.Lock()
	defer apiServerMu.Unlock()
	return apiServer != nil
}

func logAPIWarn(log *slog.Logger, msg string, keyValues ...any) {
	if log != nil {
		log.Warn(msg, keyValues...)
	}
}

func logAPIError(log *slog.Logger, msg string, keyValues ...any) {
	if log != nil {
		log.Error(msg, keyValues...)
	}
}
