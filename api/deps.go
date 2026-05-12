// Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
// SPDX-License-Identifier: GPL-2.0-only

package api

import (
	"dhcplane/config"
	"dhcplane/dhcpserver"
)

// Deps holds live references for HTTP handlers (no global singleton).
type Deps struct {
	DB           *dhcpserver.LeaseDB
	Cfg          func() *config.Config
	Reservations func() config.Reservations
	DHCPServing  func() bool
	AppVersion   string
	AuthToken    func() string
}
