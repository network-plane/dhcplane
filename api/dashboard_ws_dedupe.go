// Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
// SPDX-License-Identifier: GPL-2.0-only

package api

import (
	"encoding/json"
	"fmt"
	"strings"

	"dhcplane/statistics"
)

// dhcpDashboardWSPushFingerprint returns a compact string for comparing dashboard payloads
// so WebSocket does not re-send full JSON when only irrelevant fields drift.
func dhcpDashboardWSPushFingerprint(p map[string]any) string {
	var buf strings.Builder
	if c, ok := p["counters"].(map[string]any); ok {
		keys := []string{
			"allocations_last_1m", "allocations_last_1h", "allocations_last_24h",
			"allocations_last_7d", "allocations_last_30d",
			"leases_current", "leases_expiring", "leases_expired",
		}
		for _, k := range keys {
			fmt.Fprintf(&buf, "%v:", c[k])
		}
	}
	buf.WriteByte('|')
	if lv, ok := p["lease_views"].(map[string]any); ok {
		for _, k := range []string{"current", "expiring", "expired"} {
			if a, ok := lv[k].([]any); ok {
				fmt.Fprintf(&buf, "%d,", len(a))
			}
		}
	}
	buf.WriteByte('|')
	if lp, ok := p["leases_preview"].([]any); ok {
		fmt.Fprintf(&buf, "n=%d", len(lp))
		for i, row := range lp {
			if i >= 8 {
				break
			}
			if m, ok := row.(map[string]any); ok {
				fmt.Fprintf(&buf, ";%v", m["ip"])
			}
		}
	}
	buf.WriteByte('|')
	if st, ok := p["status"].(map[string]any); ok {
		fmt.Fprintf(&buf, "r=%v d=%v a=%v", st["ready"], st["dhcp_up"], st["api_up"])
		if feat, ok := st["features"]; ok {
			if b, err := json.Marshal(feat); err == nil {
				buf.WriteByte('|')
				buf.Write(b)
			}
		}
	}
	buf.WriteByte('|')
	if b, ok := p["build"].(map[string]any); ok {
		fmt.Fprintf(&buf, "v=%v", b["version"])
	}
	if dh, ok := p["dhcp"].(map[string]any); ok {
		fmt.Fprintf(&buf, "|sn=%v|if=%v|rsv=%v", dh["subnet_cidr"], dh["interface"], dh["reservations_n"])
	}
	fmt.Fprintf(&buf, "|sd=%v", p["subnet_detail_count"])
	if raw, ok := p["allocation_events_1h"]; ok {
		if ev, ok := raw.([]statistics.AllocationEvent); ok {
			fmt.Fprintf(&buf, "|ael=%d", len(ev))
			if len(ev) > 0 {
				fmt.Fprintf(&buf, "|aef=%d|aeL=%d", ev[0].At, ev[len(ev)-1].At)
			}
		}
	}
	return buf.String()
}
