// Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
// SPDX-License-Identifier: GPL-2.0-only

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"dhcplane/config"
	"dhcplane/dhcpserver"
)

func testRouter(deps *Deps, token string) http.Handler {
	if deps.AuthToken == nil {
		deps.AuthToken = func() string { return token }
	}
	return buildRouter(deps, &ListenOptions{})
}

func TestHealth(t *testing.T) {
	var dhcp atomic.Bool
	dhcp.Store(true)
	h := testRouter(&Deps{
		DHCPServing: dhcp.Load,
		AppVersion:  "test",
	}, "")
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health: got %d", rec.Code)
	}
}

func TestVersionJSON(t *testing.T) {
	h := testRouter(&Deps{
		AppVersion: "0.0.1-test",
		DHCPServing: func() bool {
			return true
		},
	}, "")
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("version: got %d", rec.Code)
	}
	var m map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["version"] != "0.0.1-test" {
		t.Fatalf("version field: %q", m["version"])
	}
}

func TestReadyDHCPDown503(t *testing.T) {
	h := testRouter(&Deps{
		AppVersion:  "test",
		DHCPServing: func() bool { return false },
	}, "")
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready: want 503 got %d", rec.Code)
	}
}

func TestReadyDHCPUp200(t *testing.T) {
	h := testRouter(&Deps{
		AppVersion:  "test",
		DHCPServing: func() bool { return true },
	}, "")
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ready: want 200 got %d", rec.Code)
	}
}

func TestAuthRequired(t *testing.T) {
	deps := &Deps{
		AppVersion: "test",
		DHCPServing: func() bool {
			return true
		},
		AuthToken: func() string { return "secret" },
	}
	h := buildRouter(deps, &ListenOptions{})

	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("version without token: want 401 got %d", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("health should stay exempt: got %d", rec2.Code)
	}

	req3 := httptest.NewRequest(http.MethodGet, "/version", nil)
	req3.Header.Set("Authorization", "Bearer secret")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("version with bearer: want 200 got %d", rec3.Code)
	}
}

func TestDHCPReservations(t *testing.T) {
	res := config.Reservations{
		"aa:bb:cc:dd:ee:ff": {IP: "192.0.2.10", Note: "x"},
	}
	h := testRouter(&Deps{
		AppVersion: "test",
		Reservations: func() config.Reservations {
			return res
		},
		DHCPServing: func() bool { return true },
	}, "")
	req := httptest.NewRequest(http.MethodGet, "/dhcp/reservations", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reservations: %d", rec.Code)
	}
}

func TestDHCPLeases(t *testing.T) {
	db := dhcpserver.NewLeaseDB(t.TempDir() + "/leases.json")
	_ = db.Load()
	db.Set(dhcpserver.Lease{IP: "192.0.2.2", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "h", AllocatedAt: 1, Expiry: 9999999999, FirstSeen: 1})
	h := testRouter(&Deps{
		DB:          db,
		AppVersion:  "test",
		DHCPServing: func() bool { return true },
	}, "")
	req := httptest.NewRequest(http.MethodGet, "/dhcp/leases", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
}