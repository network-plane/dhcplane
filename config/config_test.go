// Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
// SPDX-License-Identifier: GPL-2.0-only

package config

import "testing"

func TestStatsDashboardHTMLEnabled_defaultTrue(t *testing.T) {
	var c Config
	if !c.StatsDashboardHTMLEnabled() {
		t.Fatal("unset should default to enabled")
	}
}

func TestStatsDashboardHTMLEnabled_nilReceiver(t *testing.T) {
	var c *Config
	if !c.StatsDashboardHTMLEnabled() {
		t.Fatal("nil *Config should default to enabled (same as unset)")
	}
}

func TestStatsDashboardHTMLEnabled_explicit(t *testing.T) {
	f := false
	c := Config{StatsDashboardEnabled: &f}
	if c.StatsDashboardHTMLEnabled() {
		t.Fatal("explicit false")
	}
	tr := true
	c2 := Config{StatsDashboardEnabled: &tr}
	if !c2.StatsDashboardHTMLEnabled() {
		t.Fatal("explicit true")
	}
}
