// Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
// SPDX-License-Identifier: GPL-2.0-only

package api

import (
	"fmt"
	"strconv"
	"strings"

	"dhcplane/config"
)

// dhcpDashboardStatusFeature is one card in the "Protocols & features" grid (JSON for /stats/dashboard/data).
type dhcpDashboardStatusFeature struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Value   string `json:"value"`
	Variant string `json:"variant"` // ok | warn | bad | neutral
}

func dhcpBoolFeature(key, label string, on bool) dhcpDashboardStatusFeature {
	if on {
		return dhcpDashboardStatusFeature{Key: key, Label: label, Value: "On", Variant: "ok"}
	}
	return dhcpDashboardStatusFeature{Key: key, Label: label, Value: "Off", Variant: "neutral"}
}

// buildDHCPDashboardStatusFeatures mirrors dnsplane-style feature cards for DHCP configuration.
func buildDHCPDashboardStatusFeatures(cfg *config.Config) []dhcpDashboardStatusFeature {
	if cfg == nil {
		return nil
	}
	out := make([]dhcpDashboardStatusFeature, 0, 20)

	tlsOK := strings.TrimSpace(cfg.APITLSCertFile) != "" && strings.TrimSpace(cfg.APITLSKeyFile) != ""
	if !tlsOK {
		out = append(out, dhcpDashboardStatusFeature{Key: "api_tls", Label: "API HTTPS", Value: "Off (HTTP)", Variant: "neutral"})
	} else {
		out = append(out, dhcpDashboardStatusFeature{Key: "api_tls", Label: "API HTTPS", Value: "On", Variant: "ok"})
	}
	if strings.TrimSpace(cfg.APIAuthToken) == "" {
		out = append(out, dhcpDashboardStatusFeature{Key: "api_auth", Label: "API auth", Value: "Open", Variant: "neutral"})
	} else {
		out = append(out, dhcpDashboardStatusFeature{Key: "api_auth", Label: "API auth", Value: "Bearer token", Variant: "ok"})
	}
	if cfg.APIRateLimitPerIP > 0 {
		burst := cfg.APIRateLimitBurst
		if burst <= 0 {
			burst = 20
		}
		out = append(out, dhcpDashboardStatusFeature{
			Key: "api_rl", Label: "HTTP rate limit",
			Value:   fmt.Sprintf("On · %.0f r/s · burst %d", cfg.APIRateLimitPerIP, burst),
			Variant: "ok",
		})
	} else {
		out = append(out, dhcpDashboardStatusFeature{Key: "api_rl", Label: "HTTP rate limit", Value: "Off", Variant: "neutral"})
	}

	out = append(out, dhcpBoolFeature("stats_dash", "Stats dashboard", cfg.StatsDashboardHTMLEnabled()))
	out = append(out, dhcpBoolFeature("auto_reload", "Config auto-reload", cfg.AutoReload))
	out = append(out, dhcpBoolFeature("compact_load", "Compact lease DB on load", cfg.CompactOnLoad))
	out = append(out, dhcpBoolFeature("authoritative", "DHCP authoritative", effectiveAuthoritative(cfg)))
	out = append(out, dhcpBoolFeature("bcast28", "Broadcast flag (opt 28)", cfg.EnableBroadcast28))

	d := cfg.DetectDHCPServers
	if !d.Enabled {
		out = append(out, dhcpDashboardStatusFeature{Key: "detect_dhcp", Label: "Detect other DHCP servers", Value: "Off", Variant: "neutral"})
	} else {
		mode := strings.TrimSpace(strings.ToLower(d.ActiveProbe))
		if mode == "" {
			mode = "off"
		}
		iv := d.ProbeInterval
		if iv <= 0 {
			iv = 600
		}
		switch mode {
		case "off":
			out = append(out, dhcpDashboardStatusFeature{
				Key: "detect_dhcp", Label: "Detect other DHCP servers",
				Value: fmt.Sprintf("On · passive · every %ds", iv), Variant: "ok",
			})
		default:
			out = append(out, dhcpDashboardStatusFeature{
				Key: "detect_dhcp", Label: "Detect other DHCP servers",
				Value: fmt.Sprintf("On · %s · every %ds", mode, iv), Variant: "ok",
			})
		}
	}

	a := cfg.ARPAnomalyDetection
	if !a.Enabled {
		out = append(out, dhcpDashboardStatusFeature{Key: "arp", Label: "ARP anomaly detection", Value: "Off", Variant: "neutral"})
	} else {
		pi := a.ProbeInterval
		if pi <= 0 {
			pi = 1800
		}
		out = append(out, dhcpDashboardStatusFeature{
			Key: "arp", Label: "ARP anomaly detection",
			Value: fmt.Sprintf("On · every %ds", pi), Variant: "ok",
		})
	}

	nBanned := len(cfg.BannedMACs)
	if nBanned == 0 {
		out = append(out, dhcpDashboardStatusFeature{Key: "banned", Label: "Banned MACs", Value: "None", Variant: "neutral"})
	} else {
		out = append(out, dhcpDashboardStatusFeature{
			Key: "banned", Label: "Banned MACs",
			Value: strconv.Itoa(nBanned) + " configured", Variant: "warn",
		})
	}

	return out
}
