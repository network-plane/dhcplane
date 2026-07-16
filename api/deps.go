// Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
// SPDX-License-Identifier: GPL-2.0-only

package api

import (
	"dhcplane/config"
	"dhcplane/dhcpserver"
)

// FindingEvent is a recent ARP anomaly or foreign DHCP detection event.
type FindingEvent struct {
	Kind     string `json:"kind"` // arp | foreign_dhcp
	At       string `json:"at"`
	AtUnix   int64  `json:"at_unix"`
	IP       string `json:"ip,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Iface    string `json:"iface,omitempty"`
	Reason   string `json:"reason,omitempty"`
	ServerIP string `json:"server_ip,omitempty"`
	From     string `json:"from,omitempty"`
	LeaseMAC string `json:"lease_mac,omitempty"`
	ResMAC   string `json:"res_mac,omitempty"`
	Reserved bool   `json:"reserved,omitempty"`
	Leased   bool   `json:"leased,omitempty"`
	Excluded bool   `json:"excluded,omitempty"`
	Message  string `json:"message,omitempty"`
}

// ConsoleLine is one recent server log line for the dashboard console view.
type ConsoleLine struct {
	At   string `json:"at"`
	Text string `json:"text"`
}

// ReservationMutator edits a copy of the current reservations map and returns the next map.
type ReservationMutator func(current config.Reservations) (config.Reservations, error)

// Deps holds live references for HTTP handlers (no global singleton).
type Deps struct {
	DB           *dhcpserver.LeaseDB
	Cfg          func() *config.Config
	Reservations func() config.Reservations
	DHCPServing  func() bool
	AppVersion   string
	AuthToken    func() string

	// Optional operational hooks (wired from serve).
	ConfigPath         string
	ReservationsPath   func() string
	BoundIface         func() string
	ReloadConfig       func() error
	UpdateReservations func(ReservationMutator) error
	RecentFindings     func(limit int) []FindingEvent
	ConsoleLines       func(limit int) []ConsoleLine
}
