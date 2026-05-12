// Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
// SPDX-License-Identifier: GPL-2.0-only

package api

import (
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"dhcplane/dhcpserver"
	"dhcplane/statistics"
)

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func readyHandler(w http.ResponseWriter, _ *http.Request, d *Deps) {
	apiUp := true
	dhcpUp := d != nil && d.DHCPServing != nil && d.DHCPServing()
	ready := apiUp && dhcpUp
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{
		"ready": ready,
		"api":   apiUp,
		"dhcp":  dhcpUp,
		"build": BuildInfo(d.AppVersion),
	})
}

func versionHandler(w http.ResponseWriter, _ *http.Request, d *Deps) {
	writeJSON(w, http.StatusOK, BuildInfo(d.AppVersion))
}

type leaseJSONRow struct {
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	Hostname    string `json:"hostname"`
	AllocatedAt string `json:"allocated_at"`
	Expiry      string `json:"expiry"`
	FirstSeen   string `json:"first_seen"`
}

func leasesHandler(w http.ResponseWriter, _ *http.Request, d *Deps) {
	if d.DB == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lease db unavailable"})
		return
	}
	var rows []leaseJSONRow
	d.DB.ForEach(func(l dhcpserver.Lease) {
		rows = append(rows, leaseJSONRow{
			IP:          l.IP,
			MAC:         l.MAC,
			Hostname:    l.Hostname,
			AllocatedAt: dhcpserver.FormatEpoch(l.AllocatedAt),
			Expiry:      dhcpserver.FormatEpoch(l.Expiry),
			FirstSeen:   dhcpserver.FormatEpoch(l.FirstSeen),
		})
	})
	sort.Slice(rows, func(i, j int) bool {
		return ipKey(rows[i].IP) < ipKey(rows[j].IP)
	})
	writeJSON(w, http.StatusOK, map[string]any{"leases": rows})
}

func reservationsHandler(w http.ResponseWriter, _ *http.Request, d *Deps) {
	if d.Reservations == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "reservations unavailable"})
		return
	}
	res := d.Reservations()
	writeJSON(w, http.StatusOK, map[string]any{"reservations": res})
}

func statsHandler(w http.ResponseWriter, r *http.Request, d *Deps) {
	if d.DB == nil || d.Cfg == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "stats unavailable"})
		return
	}
	cfg := d.Cfg()
	if cfg == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "config unavailable"})
		return
	}
	assume := time.Duration(cfg.LeaseSeconds) * time.Second
	now := time.Now()

	bannedSet := make(map[string]struct{})
	for m := range cfg.BannedMACs {
		if nm, err := dhcpserver.CanonMAC(m); err == nil {
			bannedSet[nm] = struct{}{}
		} else {
			nm := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(m), "-", ":"), " ", ""))
			bannedSet[nm] = struct{}{}
		}
	}
	for nm := range dhcpserver.ParseBannedMACsEnv() {
		bannedSet[nm] = struct{}{}
	}
	isBanned := func(mac string) bool {
		if nm, err := dhcpserver.CanonMAC(mac); err == nil {
			_, ok := bannedSet[nm]
			return ok
		}
		nm := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(mac), "-", ":"), " ", ""))
		_, ok := bannedSet[nm]
		return ok
	}

	iter := func(yield func(statistics.LeaseLite)) {
		d.DB.ForEach(func(l dhcpserver.Lease) {
			yield(statistics.LeaseLite{
				IP:          l.IP,
				MAC:         l.MAC,
				Hostname:    l.Hostname,
				AllocatedAt: l.AllocatedAt,
				Expiry:      l.Expiry,
			})
		})
	}
	isDeclined := func(ip string) bool { return d.DB.IsDeclined(ip) }

	perMinute, perHour, perDay, perWeek, perMonth := statistics.CountAllocations(iter, assume, now)
	curr, expiring, expired := statistics.ClassifyLeases(iter, assume, now)

	resp := map[string]any{
		"allocations": map[string]int{
			"last_1m":  perMinute,
			"last_1h":  perHour,
			"last_24h": perDay,
			"last_7d":  perWeek,
			"last_30d": perMonth,
		},
		"leases": map[string]int{
			"current":   len(curr),
			"expiring":  len(expiring),
			"expired":   len(expired),
			"lease_ttl": cfg.LeaseSeconds,
		},
		"lease_views": map[string][]statistics.LeaseView{
			"current":   curr,
			"expiring":  expiring,
			"expired":   expired,
		},
	}

	if detailsQuery(r) {
		rows, err := statistics.BuildDetailRows(*cfg, d.Reservations(), iter, isDeclined, isBanned, now)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		resp["details"] = rows
	}

	writeJSON(w, http.StatusOK, resp)
}

func detailsQuery(r *http.Request) bool {
	q := strings.TrimSpace(r.URL.Query().Get("details"))
	switch strings.ToLower(q) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func ipKey(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return ^uint32(0)
	}
	return dhcpserver.IPToU32(ip)
}
