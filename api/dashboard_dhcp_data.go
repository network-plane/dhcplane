// Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
// SPDX-License-Identifier: GPL-2.0-only

package api

import (
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"dhcplane/config"
	"dhcplane/dhcpserver"
	"dhcplane/statistics"
)

const dashboardLeasePreviewMax = 50

type leasePreviewRow struct {
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	Hostname    string `json:"hostname,omitempty"`
	AllocatedAt string `json:"allocated_at"`
	Expiry      string `json:"expiry"`
	FirstSeen   string `json:"first_seen"`
}

func effectiveAuthoritative(cfg *config.Config) bool {
	if cfg == nil || cfg.Authoritative == nil {
		return true
	}
	return *cfg.Authoritative
}

// buildDHCPDashboardPayload returns JSON for GET /stats/dashboard/data and WebSocket pushes.
func buildDHCPDashboardPayload(d *Deps) map[string]any {
	if d == nil {
		return map[string]any{"error": "no deps"}
	}
	cfg := d.Cfg()
	if cfg == nil {
		return map[string]any{"error": "no config"}
	}
	dhcpUp := d.DHCPServing != nil && d.DHCPServing()
	ready := dhcpUp

	status := map[string]any{
		"ready":     ready,
		"dhcp_up":   dhcpUp,
		"api_up":    true,
		"listeners": map[string]any{},
	}
	if cfg.API && strings.TrimSpace(cfg.APIPort) != "" {
		addr := formatDashboardAPIAddr(cfg)
		status["listeners"] = map[string]any{
			"api_port":    strings.TrimSpace(cfg.APIPort),
			"api_bind":    strings.TrimSpace(cfg.APIBind),
			"api_address": addr,
			"api_tls":     cfg.APITLSCertFile != "" && cfg.APITLSKeyFile != "",
		}
	}

	dhcpBlock := map[string]any{
		"interface":      cfg.Interface,
		"server_ip":      cfg.ServerIP,
		"subnet_cidr":    cfg.SubnetCIDR,
		"gateway":        cfg.Gateway,
		"lease_db_path":  cfg.LeaseDBPath,
		"authoritative":  effectiveAuthoritative(cfg),
		"lease_seconds":  cfg.LeaseSeconds,
		"reservations_n": 0,
		"console_tcp":    strings.TrimSpace(cfg.ConsoleTCPAddress),
	}
	if d.Reservations != nil {
		dhcpBlock["reservations_n"] = len(d.Reservations())
	}

	payload := map[string]any{
		"build":   BuildInfo(d.AppVersion),
		"status":  status,
		"dhcp":    dhcpBlock,
		"summary": map[string]any{},
	}

	if d.DB == nil {
		payload["summary"] = map[string]any{"error": "lease db unavailable"}
		return payload
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

	payload["counters"] = map[string]any{
		"allocations_last_1m":  perMinute,
		"allocations_last_1h":  perHour,
		"allocations_last_24h": perDay,
		"allocations_last_7d":  perWeek,
		"allocations_last_30d": perMonth,
		"leases_current":       len(curr),
		"leases_expiring":      len(expiring),
		"leases_expired":       len(expired),
	}
	payload["lease_views"] = map[string][]statistics.LeaseView{
		"current":  curr,
		"expiring": expiring,
		"expired":  expired,
	}

	var previews []leasePreviewRow
	d.DB.ForEach(func(l dhcpserver.Lease) {
		previews = append(previews, leasePreviewRow{
			IP:          l.IP,
			MAC:         l.MAC,
			Hostname:    l.Hostname,
			AllocatedAt: dhcpserver.FormatEpoch(l.AllocatedAt),
			Expiry:      dhcpserver.FormatEpoch(l.Expiry),
			FirstSeen:   dhcpserver.FormatEpoch(l.FirstSeen),
		})
	})
	sort.Slice(previews, func(i, j int) bool {
		return dashboardIPKey(previews[i].IP) < dashboardIPKey(previews[j].IP)
	})
	if len(previews) > dashboardLeasePreviewMax {
		previews = previews[:dashboardLeasePreviewMax]
	}
	payload["leases_preview"] = previews

	var reservations config.Reservations
	if d.Reservations != nil {
		reservations = d.Reservations()
	}
	detailRows, err := statistics.BuildDetailRows(*cfg, reservations, iter, isDeclined, isBanned, now)
	if err == nil {
		payload["subnet_detail_count"] = len(detailRows)
	}

	return payload
}

func formatDashboardAPIAddr(cfg *config.Config) string {
	p := strings.TrimSpace(cfg.APIPort)
	b := strings.TrimSpace(cfg.APIBind)
	if p == "" {
		return ""
	}
	if b != "" {
		return net.JoinHostPort(b, p)
	}
	return ":" + p
}

func dashboardIPKey(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return ^uint32(0)
	}
	return dhcpserver.IPToU32(ip)
}

func dashboardDataHandler(w http.ResponseWriter, r *http.Request, d *Deps) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg := d.Cfg()
	if !requireStatsDashboard(w, r, cfg != nil && cfg.StatsDashboardHTMLEnabled()) {
		return
	}
	writeJSON(w, http.StatusOK, buildDHCPDashboardPayload(d))
}

func dashboardPageHandler(w http.ResponseWriter, r *http.Request, d *Deps) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg := d.Cfg()
	if !requireStatsDashboard(w, r, cfg != nil && cfg.StatsDashboardHTMLEnabled()) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(dhcpDashboardHTML))
}
