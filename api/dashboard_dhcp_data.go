// Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
// SPDX-License-Identifier: GPL-2.0-only

package api

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	AllocatedTS int64  `json:"allocated_ts"`
	ExpiryTS    int64  `json:"expiry_ts"`
	FirstSeenTS int64  `json:"first_seen_ts"`
}

type configMACRow struct {
	Kind                string `json:"kind"`
	MAC                 string `json:"mac"`
	IP                  string `json:"ip,omitempty"`
	Note                string `json:"note,omitempty"`
	FirstSeen           string `json:"first_seen,omitempty"`
	FirstSeenTS         int64  `json:"first_seen_ts"`
	EquipmentType       string `json:"equipment_type,omitempty"`
	Manufacturer        string `json:"manufacturer,omitempty"`
	ManagementType      string `json:"management_type,omitempty"`
	ManagementInterface string `json:"management_interface,omitempty"`
}

func effectiveAuthoritative(cfg *config.Config) bool {
	if cfg == nil || cfg.Authoritative == nil {
		return true
	}
	return *cfg.Authoritative
}

// consoleSocketPrimaryHint returns the first UNIX socket path the console tries to bind
// (aligned with main.consoleSocketCandidates).
func consoleSocketPrimaryHint() string {
	candidates := []string{
		"/run/dhcplane/consoleui.sock",
		"/tmp/consoleui.sock",
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		candidates = append(candidates, filepath.Join(xdg, "dhcplane.sock"))
	}
	if len(candidates) == 0 {
		return "—"
	}
	return candidates[0]
}

func buildDHCStatusListeners(cfg *config.Config) map[string]any {
	if cfg == nil {
		return map[string]any{}
	}
	out := map[string]any{
		"dhcp_port":     "67 / 68",
		"api_enabled":   cfg.API,
		"api_tls":       cfg.APITLSCertFile != "" && cfg.APITLSKeyFile != "",
		"client_socket": consoleSocketPrimaryHint(),
		"client_tcp":    strings.TrimSpace(cfg.ConsoleTCPAddress),
	}
	if cfg.API && strings.TrimSpace(cfg.APIPort) != "" {
		out["api_port"] = strings.TrimSpace(cfg.APIPort)
		out["api_bind"] = strings.TrimSpace(cfg.APIBind)
		out["api_address"] = formatDashboardAPIAddr(cfg)
	} else {
		out["api_port"] = "—"
		out["api_bind"] = ""
		out["api_address"] = "—"
	}
	return out
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
	apiUp := Running()

	status := map[string]any{
		"ready":     ready,
		"dhcp_up":   dhcpUp,
		"api_up":    apiUp,
		"listeners": buildDHCStatusListeners(cfg),
		"features":  buildDHCPDashboardStatusFeatures(cfg),
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
		"banned_macs_n":  len(cfg.BannedMACs),
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

	perMinute, perHour, perDay, perWeek, perMonth := statistics.CountAllocations(iter, assume, now)
	allocEvents1h := statistics.ListAllocationEventsInWindow(iter, assume, now, time.Hour, statistics.MaxDashboardAllocationEvents)
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
	payload["allocation_events_1h"] = allocEvents1h
	payload["server_now_unix"] = now.Unix()

	var previews []leasePreviewRow
	d.DB.ForEach(func(l dhcpserver.Lease) {
		previews = append(previews, leasePreviewRow{
			IP:          l.IP,
			MAC:         l.MAC,
			Hostname:    l.Hostname,
			AllocatedAt: dhcpserver.FormatEpoch(l.AllocatedAt),
			Expiry:      dhcpserver.FormatEpoch(l.Expiry),
			FirstSeen:   dhcpserver.FormatEpoch(l.FirstSeen),
			AllocatedTS: l.AllocatedAt,
			ExpiryTS:    l.Expiry,
			FirstSeenTS: l.FirstSeen,
		})
	})
	sort.Slice(previews, func(i, j int) bool {
		return dashboardIPKey(previews[i].IP) < dashboardIPKey(previews[j].IP)
	})
	if len(previews) > dashboardLeasePreviewMax {
		previews = previews[:dashboardLeasePreviewMax]
	}
	payload["leases_preview"] = previews

	var allLeases []leasePreviewRow
	d.DB.ForEach(func(l dhcpserver.Lease) {
		allLeases = append(allLeases, leasePreviewRow{
			IP:          l.IP,
			MAC:         l.MAC,
			Hostname:    l.Hostname,
			AllocatedAt: dhcpserver.FormatEpoch(l.AllocatedAt),
			Expiry:      dhcpserver.FormatEpoch(l.Expiry),
			FirstSeen:   dhcpserver.FormatEpoch(l.FirstSeen),
			AllocatedTS: l.AllocatedAt,
			ExpiryTS:    l.Expiry,
			FirstSeenTS: l.FirstSeen,
		})
	})
	sort.Slice(allLeases, func(i, j int) bool {
		return dashboardIPKey(allLeases[i].IP) < dashboardIPKey(allLeases[j].IP)
	})
	payload["leases_all"] = allLeases

	var reservations config.Reservations
	if d.Reservations != nil {
		reservations = d.Reservations()
	}
	configMACs := make([]configMACRow, 0, len(reservations)+len(cfg.BannedMACs))
	for mac, r := range reservations {
		configMACs = append(configMACs, configMACRow{
			Kind:                "reservation",
			MAC:                 mac,
			IP:                  r.IP,
			Note:                r.Note,
			FirstSeen:           dhcpserver.FormatEpoch(r.FirstSeen),
			FirstSeenTS:         r.FirstSeen,
			EquipmentType:       r.EquipmentType,
			Manufacturer:        r.Manufacturer,
			ManagementType:      r.ManagementType,
			ManagementInterface: r.ManagementInterface,
		})
	}
	for mac, meta := range cfg.BannedMACs {
		configMACs = append(configMACs, configMACRow{
			Kind:                "banned",
			MAC:                 mac,
			Note:                meta.Note,
			FirstSeen:           dhcpserver.FormatEpoch(meta.FirstSeen),
			FirstSeenTS:         meta.FirstSeen,
			EquipmentType:       meta.EquipmentType,
			Manufacturer:        meta.Manufacturer,
			ManagementType:      meta.ManagementType,
			ManagementInterface: meta.ManagementInterface,
		})
	}
	sort.Slice(configMACs, func(i, j int) bool {
		a, b := configMACs[i], configMACs[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return strings.ToLower(a.MAC) < strings.ToLower(b.MAC)
	})
	payload["config_macs"] = configMACs
	detailRows, counts, err := buildSubnetDetailPayload(d)
	if err == nil {
		payload["subnet_detail_count"] = len(detailRows)
		payload["subnet_details"] = detailRows
		payload["subnet_counts"] = counts
		payload["subnet_grid"] = buildSubnetGridCells(detailRows)
	}
	if d.RecentFindings != nil {
		payload["findings"] = d.RecentFindings(100)
	} else {
		payload["findings"] = []FindingEvent{}
	}
	if d.ConsoleLines != nil {
		payload["console_lines"] = d.ConsoleLines(250)
	} else {
		payload["console_lines"] = []ConsoleLine{}
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
	showTokenPanel := cfg != nil && strings.TrimSpace(cfg.APIAuthToken) != ""
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(buildDHCPDashboardHTML(showTokenPanel)))
}
