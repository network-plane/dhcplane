# Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
# SPDX-License-Identifier: GPL-2.0-only

BINARY      ?= dhcplane
PKG         ?= .
GO          ?= go
CGO_ENABLED ?= 0
GO_TAGS     ?= netgo,osusergo
LDFLAGS     ?= -s -w -extldflags "-static"

# Cross-compile defaults for Linux servers (override as needed).
GOOS        ?=
GOARCH      ?=

export CGO_ENABLED

.PHONY: all build linux linux-amd64 linux-arm64 test clean install fmt vet

all: build

build:
	$(GO) build -trimpath -tags '$(GO_TAGS)' -ldflags '$(LDFLAGS)' -o $(BINARY) $(PKG)

# Static Linux binary for deployment (from macOS/Linux).
# Example: make linux-amd64
linux:
	CGO_ENABLED=0 GOOS=$(or $(GOOS),linux) GOARCH=$(or $(GOARCH),amd64) \
		$(GO) build -trimpath -tags '$(GO_TAGS)' -ldflags '$(LDFLAGS)' -o $(BINARY) $(PKG)

linux-amd64:
	@$(MAKE) linux GOOS=linux GOARCH=amd64 BINARY=$(BINARY)

linux-arm64:
	@$(MAKE) linux GOOS=linux GOARCH=arm64 BINARY=$(BINARY)

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

install:
	$(GO) install -trimpath -tags '$(GO_TAGS)' -ldflags '$(LDFLAGS)' $(PKG)

clean:
	rm -f $(BINARY)
