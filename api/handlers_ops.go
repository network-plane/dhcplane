// Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
// SPDX-License-Identifier: GPL-2.0-only

package api

import (
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"dhcplane/arp"
	"dhcplane/config"
	"dhcplane/dhcpserver"
	"dhcplane/statistics"
)

var (
	arpScanMu       sync.Mutex
	arpScanLastUnix int64
)

func searchIPHandler(w http.ResponseWriter, r *http.Request, d *Deps) {
	ipStr := strings.TrimSpace(chi.URLParam(r, "ip"))
	if ipStr == "" {
		ipStr = strings.TrimSpace(r.URL.Query().Get("ip"))
	}
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid IPv4 address"})
		return
	}
	writeJSON(w, http.StatusOK, buildIPSearchResult(d, ip.String()))
}

func buildIPSearchResult(d *Deps, ip string) map[string]any {
	out := map[string]any{
		"ip":          ip,
		"reservation": nil,
		"lease":       nil,
		"found":       false,
	}
	var resMAC string
	var reservation *config.Reservation
	if d.Reservations != nil {
		for mac, res := range d.Reservations() {
			if strings.TrimSpace(res.IP) == ip {
				cp := res
				reservation = &cp
				resMAC = mac
				break
			}
		}
	}
	if reservation != nil {
		out["found"] = true
		out["reservation"] = map[string]any{
			"mac":                  resMAC,
			"ip":                   reservation.IP,
			"note":                 reservation.Note,
			"first_seen":           dhcpserver.FormatEpoch(reservation.FirstSeen),
			"first_seen_ts":        reservation.FirstSeen,
			"equipment_type":       reservation.EquipmentType,
			"manufacturer":         reservation.Manufacturer,
			"management_type":      reservation.ManagementType,
			"management_interface": reservation.ManagementInterface,
		}
	}
	if d.DB != nil {
		if lease, ok := d.DB.FindByIP(ip); ok {
			out["found"] = true
			out["lease"] = map[string]any{
				"ip":            lease.IP,
				"mac":           lease.MAC,
				"hostname":      lease.Hostname,
				"allocated_at":  dhcpserver.FormatEpoch(lease.AllocatedAt),
				"expiry":        dhcpserver.FormatEpoch(lease.Expiry),
				"first_seen":    dhcpserver.FormatEpoch(lease.FirstSeen),
				"allocated_ts":  lease.AllocatedAt,
				"expiry_ts":     lease.Expiry,
				"first_seen_ts": lease.FirstSeen,
				"expired":       lease.Expiry > 0 && time.Now().Unix() > lease.Expiry,
			}
			if reservation != nil {
				out["mac_mismatch"] = !macEqualLoose(resMAC, lease.MAC)
			}
		}
	}
	return out
}

func macEqualLoose(a, b string) bool {
	na, ea := dhcpserver.CanonMAC(a)
	nb, eb := dhcpserver.CanonMAC(b)
	if ea == nil && eb == nil {
		return na == nb
	}
	return strings.EqualFold(strings.ReplaceAll(a, "-", ":"), strings.ReplaceAll(b, "-", ":"))
}

func subnetDetailsHandler(w http.ResponseWriter, r *http.Request, d *Deps) {
	rows, counts, err := buildSubnetDetailPayload(d)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"details": rows,
		"counts":  counts,
		"grid":    buildSubnetGridCells(rows),
	})
}

type subnetDetailJSON struct {
	IP          string `json:"ip"`
	Type        string `json:"type"`
	MAC         string `json:"mac,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	AllocatedAt string `json:"allocated_at,omitempty"`
	Expiry      string `json:"expiry,omitempty"`
	AllocatedTS int64  `json:"allocated_ts"`
	ExpiryTS    int64  `json:"expiry_ts"`
}

func buildSubnetDetailPayload(d *Deps) ([]subnetDetailJSON, map[string]int, error) {
	if d == nil || d.Cfg == nil || d.DB == nil {
		return nil, nil, errUnavailable("subnet details unavailable")
	}
	cfg := d.Cfg()
	if cfg == nil {
		return nil, nil, errUnavailable("config unavailable")
	}
	var reservations config.Reservations
	if d.Reservations != nil {
		reservations = d.Reservations()
	}
	now := time.Now()
	bannedSet := bannedMACSet(cfg)
	isBanned := func(mac string) bool { return isBannedMAC(bannedSet, mac) }
	iter := func(yield func(statistics.LeaseLite)) {
		d.DB.ForEach(func(l dhcpserver.Lease) {
			yield(statistics.LeaseLite{
				IP: l.IP, MAC: l.MAC, Hostname: l.Hostname,
				AllocatedAt: l.AllocatedAt, Expiry: l.Expiry,
			})
		})
	}
	isDeclined := func(ip string) bool { return d.DB.IsDeclined(ip) }
	raw, err := statistics.BuildDetailRows(*cfg, reservations, iter, isDeclined, isBanned, now)
	if err != nil {
		return nil, nil, err
	}
	counts := map[string]int{}
	rows := make([]subnetDetailJSON, 0, len(raw))
	for _, r := range raw {
		counts[r.Type]++
		rows = append(rows, subnetDetailJSON{
			IP:          r.IP,
			Type:        r.Type,
			MAC:         r.MAC,
			Hostname:    r.Hostname,
			AllocatedAt: dhcpserver.FormatEpoch(r.AllocatedAt),
			Expiry:      dhcpserver.FormatEpoch(r.Expiry),
			AllocatedTS: r.AllocatedAt,
			ExpiryTS:    r.Expiry,
		})
	}
	return rows, counts, nil
}

func buildSubnetGridCells(rows []subnetDetailJSON) []map[string]string {
	out := make([]map[string]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]string{"ip": r.IP, "type": r.Type})
	}
	return out
}

func bannedMACSet(cfg *config.Config) map[string]struct{} {
	bannedSet := make(map[string]struct{})
	if cfg == nil {
		return bannedSet
	}
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
	return bannedSet
}

func isBannedMAC(set map[string]struct{}, mac string) bool {
	if nm, err := dhcpserver.CanonMAC(mac); err == nil {
		_, ok := set[nm]
		return ok
	}
	nm := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(mac), "-", ":"), " ", ""))
	_, ok := set[nm]
	return ok
}

type simpleError string

func (e simpleError) Error() string { return string(e) }

func errUnavailable(msg string) error { return simpleError(msg) }

func arpScanHandler(w http.ResponseWriter, r *http.Request, d *Deps) {
	if d == nil || d.Cfg == nil || d.DB == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "arp scan unavailable"})
		return
	}
	cfg := d.Cfg()
	if cfg == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "config unavailable"})
		return
	}

	arpScanMu.Lock()
	defer arpScanMu.Unlock()
	now := time.Now().Unix()
	if now-arpScanLastUnix < 5 {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "ARP scan rate limited (wait a few seconds)"})
		return
	}
	arpScanLastUnix = now

	iface := strings.TrimSpace(r.URL.Query().Get("iface"))
	if iface == "" && d.BoundIface != nil {
		iface = strings.TrimSpace(d.BoundIface())
	}
	if iface == "" {
		iface = strings.TrimSpace(cfg.Interface)
	}
	allIfaces := queryTruthy(r, "all_ifaces")
	var reservations config.Reservations
	if d.Reservations != nil {
		reservations = d.Reservations()
	}
	entries, findings, err := arp.Scan(cfg, reservations, d.DB, iface, allIfaces, 3*time.Second)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		ki, kj := ipKey(entries[i].IP), ipKey(entries[j].IP)
		if ki == kj {
			return entries[i].Iface < entries[j].Iface
		}
		return ki < kj
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"iface":      iface,
		"entries":    entries,
		"findings":   findings,
		"scanned_at": dhcpserver.FormatEpoch(now),
	})
}

func queryTruthy(r *http.Request, key string) bool {
	q := strings.TrimSpace(r.URL.Query().Get(key))
	switch strings.ToLower(q) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func reservationAddHandler(w http.ResponseWriter, r *http.Request, d *Deps) {
	if d == nil || d.UpdateReservations == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "reservation updates not available"})
		return
	}
	var body struct {
		MAC  string `json:"mac"`
		IP   string `json:"ip"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	norm, err := dhcpserver.CanonMAC(body.MAC)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mac"})
		return
	}
	ip := net.ParseIP(strings.TrimSpace(body.IP)).To4()
	if ip == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid IPv4"})
		return
	}
	note := strings.TrimSpace(body.Note)
	warns := []string{}
	if d.Cfg != nil {
		if cfg := d.Cfg(); cfg != nil {
			if _, subnet, cerr := net.ParseCIDR(cfg.SubnetCIDR); cerr == nil && !subnet.Contains(ip) {
				warns = append(warns, "IP not in configured subnet")
			}
		}
	}
	if d.DB != nil {
		if l, ok := d.DB.FindByIP(ip.String()); ok && !macEqualLoose(l.MAC, norm) {
			warns = append(warns, "IP currently leased to a different MAC")
		}
	}
	var created bool
	err = d.UpdateReservations(func(current config.Reservations) (config.Reservations, error) {
		next := cloneReservations(current)
		for macKey, res := range next {
			if macEqualLoose(macKey, norm) {
				continue
			}
			if strings.TrimSpace(res.IP) == ip.String() {
				return nil, simpleError("IP already reserved for another MAC")
			}
		}
		now := time.Now().Unix()
		prev, existed := next[norm]
		created = !existed
		if !existed {
			next[norm] = config.Reservation{IP: ip.String(), Note: note, FirstSeen: now}
		} else {
			fs := prev.FirstSeen
			if fs == 0 {
				fs = now
			}
			next[norm] = config.Reservation{
				IP:                  ip.String(),
				Note:                note,
				FirstSeen:           fs,
				EquipmentType:       prev.EquipmentType,
				Manufacturer:        prev.Manufacturer,
				ManagementType:      prev.ManagementType,
				ManagementInterface: prev.ManagementInterface,
			}
		}
		return next, nil
	})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"created":  created,
		"mac":      norm,
		"ip":       ip.String(),
		"note":     note,
		"warnings": warns,
	})
}

func reservationDeleteHandler(w http.ResponseWriter, r *http.Request, d *Deps) {
	if d == nil || d.UpdateReservations == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "reservation updates not available"})
		return
	}
	mac := strings.TrimSpace(chi.URLParam(r, "mac"))
	norm, err := dhcpserver.CanonMAC(mac)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mac"})
		return
	}
	var removed bool
	err = d.UpdateReservations(func(current config.Reservations) (config.Reservations, error) {
		next := cloneReservations(current)
		if _, ok := next[norm]; !ok {
			return next, nil
		}
		delete(next, norm)
		removed = true
		return next, nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed, "mac": norm})
}

func cloneReservations(in config.Reservations) config.Reservations {
	out := make(config.Reservations, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func reloadHandler(w http.ResponseWriter, r *http.Request, d *Deps) {
	if d == nil || d.ReloadConfig == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "reload not available"})
		return
	}
	if err := d.ReloadConfig(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "reload signaled"})
}

func checkHandler(w http.ResponseWriter, r *http.Request, d *Deps) {
	path := ""
	if d != nil {
		path = strings.TrimSpace(d.ConfigPath)
	}
	if path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "config path unavailable"})
		return
	}
	raw, reservations, reservationsPath, jerr := config.ParseStrict(path)
	if jerr != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": jerr.Error(),
			"path":  path,
			"stage": "parse",
		})
		return
	}
	cfg, warns, verr := config.ValidateAndNormalizeConfig(raw)
	if verr != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       false,
			"error":    verr.Error(),
			"path":     path,
			"stage":    "validate",
			"warnings": warns,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"path":              path,
		"reservations_path": reservationsPath,
		"reservations_n":    len(reservations),
		"subnet_cidr":       cfg.SubnetCIDR,
		"server_ip":         cfg.ServerIP,
		"warnings":          warns,
	})
}

func findingsHandler(w http.ResponseWriter, r *http.Request, d *Deps) {
	limit := 100
	if d == nil || d.RecentFindings == nil {
		writeJSON(w, http.StatusOK, map[string]any{"findings": []FindingEvent{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": d.RecentFindings(limit)})
}

func consoleLinesHandler(w http.ResponseWriter, r *http.Request, d *Deps) {
	limit := 300
	if d == nil || d.ConsoleLines == nil {
		writeJSON(w, http.StatusOK, map[string]any{"lines": []ConsoleLine{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": d.ConsoleLines(limit)})
}
