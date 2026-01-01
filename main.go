package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/logrusorgru/aurora"
	planeconsole "github.com/network-plane/planeconsole"
	"github.com/spf13/cobra"
	"gopkg.in/natefinch/lumberjack.v2"

	"dhcplane/arp"
	"dhcplane/config"
	"dhcplane/dhcpserver"
	"dhcplane/statistics"
)

var appVersion = "0.1.53"

func buildConsoleConfig(maxLines int) planeconsole.Config {
	if maxLines <= 0 {
		maxLines = planeconsole.DefaultMaxLines
	}
	return planeconsole.Config{
		MaxLines: maxLines,
		Counters: []planeconsole.CounterSpec{
			{Match: "REQUEST", CaseSensitive: false, Label: "RPM", WindowSeconds: 60},
			{Match: "ACK", CaseSensitive: false, Label: "APM", WindowSeconds: 60},
		},
		Highlights: []planeconsole.HighlightSpec{
			{Match: "BANNED-MAC", CaseSensitive: true, Style: &planeconsole.Style{FG: "red", Attrs: "b"}},
			{Match: "NAK", CaseSensitive: true, Style: &planeconsole.Style{FG: "red", Attrs: "b"}},
			{Match: "ACK", CaseSensitive: true, Style: &planeconsole.Style{FG: "green", Attrs: "b"}},
			{Match: "OFFER", CaseSensitive: true, Style: &planeconsole.Style{FG: "green", Attrs: "b"}},
			{Match: "REQUEST", CaseSensitive: true, Style: &planeconsole.Style{FG: "yellow", Attrs: "b"}},
			{Match: "DISCOVER", CaseSensitive: true, Style: &planeconsole.Style{FG: "yellow", Attrs: "b"}},
			{Match: "RELEASE", CaseSensitive: true, Style: &planeconsole.Style{FG: "yellow", Attrs: "b"}},
			{Match: "DECLINE", CaseSensitive: true, Style: &planeconsole.Style{FG: "yellow", Attrs: "b"}},
			{Match: "DETECT", CaseSensitive: true, Style: &planeconsole.Style{FG: "green", Attrs: "b"}},
			{Match: "FOREIGN-DHCP-SERVER", CaseSensitive: true, Style: &planeconsole.Style{FG: "red", Attrs: "b"}},
			{Match: "ARP-ANOMALY", CaseSensitive: true, Style: &planeconsole.Style{FG: "red", Attrs: "b"}},
		},
	}
}

func consoleSocketCandidates() []string {
	candidates := []string{
		"/run/dhcplane/consoleui.sock",
		"/tmp/consoleui.sock",
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		candidates = append(candidates, filepath.Join(xdg, "dhcplane.sock"))
	}
	return candidates
}

// multiListener wraps multiple net.Listeners and multiplexes Accept() across them.
type multiListener struct {
	listeners []net.Listener
	connCh    chan net.Conn
	errCh     chan error
	closeCh   chan struct{}
	closeOnce sync.Once
}

func newMultiListener(listeners ...net.Listener) *multiListener {
	ml := &multiListener{
		listeners: listeners,
		connCh:    make(chan net.Conn),
		errCh:     make(chan error, 1),
		closeCh:   make(chan struct{}),
	}
	for _, ln := range listeners {
		go ml.acceptLoop(ln)
	}
	return ml
}

func (ml *multiListener) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ml.closeCh:
				return
			case ml.errCh <- err:
			default:
			}
			return
		}
		select {
		case ml.connCh <- conn:
		case <-ml.closeCh:
			conn.Close()
			return
		}
	}
}

func (ml *multiListener) Accept() (net.Conn, error) {
	select {
	case conn := <-ml.connCh:
		return conn, nil
	case err := <-ml.errCh:
		return nil, err
	case <-ml.closeCh:
		return nil, net.ErrClosed
	}
}

func (ml *multiListener) Close() error {
	ml.closeOnce.Do(func() {
		close(ml.closeCh)
	})
	var lastErr error
	for _, ln := range ml.listeners {
		if err := ln.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (ml *multiListener) Addr() net.Addr {
	if len(ml.listeners) > 0 {
		return ml.listeners[0].Addr()
	}
	return nil
}

// buildConsoleBroker wires the generic console broker with our DHCP-specific counters and highlights.
// If tcpAddr is non-empty (e.g., "0.0.0.0:9090"), it listens on both UNIX socket AND TCP.
// If tcpAddr is empty, it only listens on UNIX socket.
func buildConsoleBroker(maxLines int, tcpAddr string) (*planeconsole.Broker, string) {
	opts := planeconsole.BrokerOptions{
		Config: buildConsoleConfig(maxLines),
	}

	if tcpAddr != "" {
		// Listen on BOTH UNIX socket and TCP using multiListener
		opts.ListenerFactory = func() (string, net.Listener, error) {
			var listeners []net.Listener
			var addrs []string

			// Try to create UNIX socket listener
			for _, sockPath := range consoleSocketCandidates() {
				// Remove stale socket file if it exists
				_ = os.Remove(sockPath)
				// Ensure directory exists
				if err := os.MkdirAll(filepath.Dir(sockPath), 0o755); err != nil {
					continue
				}
				unixLn, err := net.Listen("unix", sockPath)
				if err == nil {
					listeners = append(listeners, unixLn)
					addrs = append(addrs, "unix:"+sockPath)
					break
				}
			}

			// Create TCP listener
			tcpLn, err := net.Listen("tcp", tcpAddr)
			if err != nil {
				// Close any UNIX listener we created
				for _, ln := range listeners {
					ln.Close()
				}
				return "", nil, fmt.Errorf("tcp listen %s: %w", tcpAddr, err)
			}
			listeners = append(listeners, tcpLn)
			addrs = append(addrs, "tcp:"+tcpLn.Addr().String())

			if len(listeners) == 0 {
				return "", nil, fmt.Errorf("failed to create any listeners")
			}

			ml := newMultiListener(listeners...)
			return strings.Join(addrs, ", "), ml, nil
		}
		return planeconsole.NewBroker(opts), tcpAddr
	}

	// Default: UNIX socket only
	opts.SocketCandidates = consoleSocketCandidates()
	return planeconsole.NewBroker(opts), ""
}

/* ----------------- Logging ----------------- */

func setupLogger(cfg config.Config) (*log.Logger, io.Closer, error) {
	filename := cfg.Logging.Filename
	if filename == "" {
		filename = "dhcplane.log"
	}
	full := filename
	if cfg.Logging.Path != "" {
		full = filepath.Join(cfg.Logging.Path, filename)
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil && !os.IsExist(err) {
		return nil, nil, err
	}
	rot := &lumberjack.Logger{
		Filename:   full,
		MaxSize:    cfg.Logging.MaxSize,
		MaxBackups: cfg.Logging.MaxBackups,
		MaxAge:     cfg.Logging.MaxAge,
		Compress:   cfg.Logging.Compress,
	}
	lg := log.New(rot, "", log.LstdFlags|log.Lmicroseconds)
	return lg, rot, nil
}

func writePID(pidPath string) error {
	if pidPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(pidPath), 0o755); err != nil && !os.IsExist(err) {
		return err
	}
	return os.WriteFile(pidPath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644)
}

func readPID(pidPath string) (int, error) {
	b, err := os.ReadFile(pidPath)
	if err != nil {
		return 0, err
	}
	var pid int
	_, err = fmt.Sscanf(string(b), "%d", &pid)
	if err != nil {
		return 0, err
	}
	return pid, nil
}

/* ----------------- Server bootstrap ----------------- */

// logDetect prints the detection mode line to logs and console via logSink.
func logDetect(cfg *config.Config, iface string, logSink func(string, ...any)) {
	if cfg.DetectDHCPServers.Enabled {
		logSink("DETECT start mode=%s interval=%ds rate_limit=%d/min iface=%s whitelist=%d",
			strings.ToLower(strings.TrimSpace(cfg.DetectDHCPServers.ActiveProbe)),
			cfg.DetectDHCPServers.ProbeInterval,
			cfg.DetectDHCPServers.RateLimit,
			iface,
			len(cfg.DetectDHCPServers.WhitelistServers),
		)
	} else {
		logSink("DETECT disabled (config) iface=%s", iface)
	}
}

// buildServerAndRun starts the DHCP server and optional console broker, handles reloads and signals.
func buildServerAndRun(cfgPath string, enableConsole bool) error {
	// Load + validate/normalize initial config
	raw, reservations, reservationsPath, jerr := config.ParseStrict(cfgPath)
	if jerr != nil {
		return fmt.Errorf("config error: %w", jerr)
	}
	cfg, warns, verr := config.ValidateAndNormalizeConfig(raw)
	if verr != nil {
		return fmt.Errorf("config validation: %w", verr)
	}

	// Migrate leases file if needed
	leasePath := cfg.LeaseDBPath
	if err := migrateLeasesFile(leasePath); err != nil {
		return err
	}
	// Update leasePath if it was the default "leases.json" (migrated to "dhcplane.leases")
	// Also check if the old path doesn't exist but the new one does
	if leasePath == "leases.json" {
		leasePath = "dhcplane.leases"
	} else {
		// For custom paths, check if old .json version exists but new .leases doesn't
		// This handles cases where config still references old path
		leaseDir := filepath.Dir(leasePath)
		if leaseDir == "." {
			leaseDir, _ = os.Getwd()
		}
		leaseBase := filepath.Base(leasePath)
		if strings.HasSuffix(leaseBase, ".json") && strings.Contains(leaseBase, "lease") {
			oldPath := leasePath
			newBase := strings.TrimSuffix(leaseBase, ".json") + ".leases"
			newPath := filepath.Join(leaseDir, newBase)
			if _, err := os.Stat(oldPath); os.IsNotExist(err) {
				if _, err := os.Stat(newPath); err == nil {
					// Old path doesn't exist but new one does - use new path
					leasePath = newPath
				}
			}
		}
	}
	
	// Check reservations file migration
	checkReservationsFileMigration(reservationsPath)
	
	db := dhcpserver.NewLeaseDB(leasePath)
	if err := db.Load(); err != nil {
		log.Printf("lease db load: %v (continuing with empty)", err)
	}

	// Logger (file or rotating)
	lg, closer, err := setupLogger(cfg)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	defer func() {
		if closer != nil {
			_ = closer.Close()
		}
	}()

	// Optional console broker (exports console over UNIX socket and/or TCP)
	var consoleBroker *planeconsole.Broker
	if enableConsole {
		maxLines := cfg.ConsoleMaxLines
		if maxLines <= 0 {
			maxLines = planeconsole.DefaultMaxLines
		}
		var tcpAddr string
		consoleBroker, tcpAddr = buildConsoleBroker(maxLines, cfg.ConsoleTCPAddress)
		if err := consoleBroker.Start(); err != nil {
			return fmt.Errorf("console broker: %w", err)
		}
		defer consoleBroker.Stop()

		// Log which mode we're using
		if tcpAddr != "" {
			log.Printf("CONSOLE listening on UNIX socket + TCP %s", tcpAddr)
		} else {
			log.Printf("CONSOLE listening on UNIX socket")
		}
	}

	// Sinks
	logSink := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if lg != nil {
			lg.Printf("%s", msg)
		}

		ts := time.Now().Format("2006/01/02 15:04:05.000000")

		if consoleBroker != nil {
			consoleBroker.Append(ts + " " + msg)
		}

		fmt.Fprintln(os.Stdout, msg)
	}
	errorSink := func(format string, args ...any) {
		msg := fmt.Sprintf("ERROR: "+format, args...)
		if lg != nil {
			lg.Printf("%s", msg)
		}
		ts := time.Now().Format("2006/01/02 15:04:05.000000")
		if consoleBroker != nil {
			consoleBroker.Append(ts + " " + msg)
		}
		fmt.Fprintln(os.Stderr, msg)
	}

	// Log initial warnings
	for _, w := range warns {
		logSink("%s", w)
	}

	// Atomic config snapshot
	var cfgAtomic atomic.Value
	cfgAtomic.Store(&cfg)
	cfgGet := func() *config.Config { return cfgAtomic.Load().(*config.Config) }
	
	// Atomic reservations snapshot
	var reservationsAtomic atomic.Value
	reservationsAtomic.Store(reservations)
	reservationsGet := func() config.Reservations { return reservationsAtomic.Load().(config.Reservations) }

	// Authoritative getter from config (default: true when unset)
	effectiveAuthoritative := func(c *config.Config) bool {
		if c == nil || c.Authoritative == nil {
			return true
		}
		return *c.Authoritative
	}
	authorGet := func() bool { return effectiveAuthoritative(cfgGet()) }

	// One-shot compaction on initial load ONLY if enabled
	if cfg.CompactOnLoad {
		sticky := time.Duration(cfg.LeaseStickySeconds) * time.Second
		if n := db.CompactNow(sticky); n > 0 {
			logSink("LEASE-COMPACT removed=%d (on initial load)", n)
		}
	}

	// Enforce reservations immediately
	dhcpserver.EnforceReservationLeaseConsistency(db, reservations)

	// PID
	if err := writePID(cfg.PIDFile); err != nil {
		return fmt.Errorf("write pid: %w", err)
	}

	// Decoupled DHCP server
	s := dhcpserver.NewServer(db, cfgGet, reservationsGet, authorGet, logSink, errorSink)

	// Bind + Serve, with rebind support when Interface changes
	laddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 67}
	var closerUDP ioCloser
	var currentIface = cfg.Interface

	bind := func(newIface string) error {
		if closerUDP != nil {
			_ = closerUDP.Close()
			closerUDP = nil
		}
		c, err := s.BindAndServe(newIface, laddr)
		if err != nil {
			return err
		}
		closerUDP = c
		currentIface = newIface
		return nil
	}
	if err := bind(currentIface); err != nil {
		return fmt.Errorf("bind: %w (need root/CAP_NET_BIND_SERVICE)", err)
	}

	logSink("START iface=%q bind=%s server_ip=%s subnet=%s gateway=%s lease=%s sticky=%s authoritative=%v",
		currentIface, laddr.String(), cfg.ServerIP, cfg.SubnetCIDR, cfg.Gateway,
		time.Duration(cfg.LeaseSeconds)*time.Second, time.Duration(cfg.LeaseStickySeconds)*time.Second, effectiveAuthoritative(&cfg))
	if cfg.AutoReload {
		logSink("START auto_reload=true (watching %s)", cfgPath)
	}

	// DETECT announcement on startup
	logDetect(&cfg, currentIface, logSink)

	// ARP anomaly scheduler (goroutine-based)
	if cfg.ARPAnomalyDetection.Enabled {
		first := time.Duration(cfg.ARPAnomalyDetection.FirstScan) * time.Second
		ival := time.Duration(cfg.ARPAnomalyDetection.ProbeInterval) * time.Second

		stopARP := make(chan struct{})
		go func() {
			timer := time.NewTimer(first)
			defer timer.Stop()
			select {
			case <-timer.C:
				triggerARPScan(cfgGet, reservationsGet, db, currentIface, logSink, errorSink, false)
			case <-stopARP:
				return
			}
			tk := time.NewTicker(ival)
			defer tk.Stop()
			for {
				select {
				case <-tk.C:
					triggerARPScan(cfgGet, reservationsGet, db, currentIface, logSink, errorSink, false)
				case <-stopARP:
					return
				}
			}
		}()
		defer close(stopARP)
	}

	// Background task scheduler - DHCP server detection
	if cfg.DetectDHCPServers.Enabled {
		first := time.Duration(cfg.DetectDHCPServers.FirstScan) * time.Second
		ival := time.Duration(cfg.DetectDHCPServers.ProbeInterval) * time.Second

		stopDHCP := make(chan struct{})
		go func() {
			timer := time.NewTimer(first)
			defer timer.Stop()
			select {
			case <-timer.C:
				triggerDHCPServerScan(cfgGet, currentIface, logSink, errorSink)
			case <-stopDHCP:
				return
			}
			tk := time.NewTicker(ival)
			defer tk.Stop()
			for {
				select {
				case <-tk.C:
					triggerDHCPServerScan(cfgGet, currentIface, logSink, errorSink)
				case <-stopDHCP:
					return
				}
			}
		}()
		defer close(stopDHCP)
	}

	// Optional auto-reload watcher
	var watcher *fsnotify.Watcher
	var watcherErr error
		if cfg.AutoReload {
			watcher, watcherErr = startConfigWatcher(cfgPath, reservationsPath, func(newCfg config.Config, newReservations config.Reservations, newWarns []string) {
			// Compare authoritative before swapping
			oldAuth := effectiveAuthoritative(cfgGet())
			newAuth := effectiveAuthoritative(&newCfg)

			cfgAtomic.Store(&newCfg)
			reservationsAtomic.Store(newReservations)
			for _, w := range newWarns {
				logSink("%s", w)
			}
			dhcpserver.EnforceReservationLeaseConsistency(db, newReservations)
			if newCfg.CompactOnLoad {
				if n := db.CompactNow(time.Duration(newCfg.LeaseStickySeconds) * time.Second); n > 0 {
					logSink("LEASE-COMPACT removed=%d (on auto-reload)", n)
				}
			}
			if newCfg.Interface != currentIface {
				if err := bind(newCfg.Interface); err != nil {
					logSink("AUTO-RELOAD: rebind failed for iface %q: %v (keeping %q)", newCfg.Interface, err, currentIface)
				} else {
					logSink("AUTO-RELOAD: rebound to iface=%q", newCfg.Interface)
				}
			}
			if oldAuth != newAuth {
				logSink("AUTO-RELOAD: authoritative %v -> %v", oldAuth, newAuth)
			} else {
				logSink("AUTO-RELOAD: authoritative=%v", newAuth)
			}
			logSink("AUTO-RELOAD: config applied")

			// DETECT announcement after auto-reload apply
			logDetect(&newCfg, currentIface, logSink)
		}, logSink)
		if watcherErr != nil {
			logSink("AUTO-RELOAD: watcher failed: %v", watcherErr)
		}
	}

	// Signals: INT/TERM stop; HUP reload
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range sigc {
		switch sig {
		case syscall.SIGHUP:
			rawNew, reservationsNew, reservationsPathNew, jerr := config.ParseStrict(cfgPath)
			if jerr != nil {
				logSink("RELOAD: config invalid, keeping old settings: %v", jerr)
				continue
			}
			nowEpoch := time.Now().Unix()
			reservationsChanged := false
			for k, v := range reservationsNew {
				if v.FirstSeen == 0 {
					v.FirstSeen = nowEpoch
					reservationsNew[k] = v
					reservationsChanged = true
				}
			}
			if rawNew.BannedMACs == nil {
				rawNew.BannedMACs = make(map[string]config.DeviceMeta)
			}
			bannedChanged := false
			for k, v := range rawNew.BannedMACs {
				if v.FirstSeen == 0 {
					v.FirstSeen = nowEpoch
					rawNew.BannedMACs[k] = v
					bannedChanged = true
				}
			}
			if reservationsChanged {
				// Save reservations to separate file
				if err := config.SaveReservations(reservationsPathNew, reservationsNew); err != nil {
					logSink("RELOAD: failed to persist reservations first_seen update: %v", err)
				}
			}
			if bannedChanged {
				// Save banned MACs back to config file
				tmp := cfgPath + ".tmp"
				if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err == nil {
					if f2, err := os.Create(tmp); err == nil {
						enc := json.NewEncoder(f2)
						enc.SetIndent("", "  ")
						if err := enc.Encode(&rawNew); err == nil {
							_ = f2.Sync()
							_ = f2.Close()
							_ = os.Rename(tmp, cfgPath)
						} else {
							_ = f2.Close()
							_ = os.Remove(tmp)
							logSink("RELOAD: failed to persist banned_macs first_seen update: %v", err)
						}
					}
				}
			}
			newCfg, newWarns, verr := config.ValidateAndNormalizeConfig(rawNew)
			if verr != nil {
				logSink("RELOAD: validation failed, keeping old settings: %v", verr)
				continue
			}
			for _, w := range newWarns {
				logSink("%s", w)
			}

			// Compare before swap
			oldAuth := effectiveAuthoritative(cfgGet())
			newAuth := effectiveAuthoritative(&newCfg)

			cfgAtomic.Store(&newCfg)
			reservationsAtomic.Store(reservationsNew)
			dhcpserver.EnforceReservationLeaseConsistency(db, reservationsNew)
			if newCfg.CompactOnLoad {
				if n := db.CompactNow(time.Duration(newCfg.LeaseStickySeconds) * time.Second); n > 0 {
					logSink("LEASE-COMPACT removed=%d (on config reload)", n)
				}
			}
			if newCfg.Interface != currentIface {
				if err := bind(newCfg.Interface); err != nil {
					logSink("RELOAD: rebind failed for iface %q: %v (keeping %q)", newCfg.Interface, err, currentIface)
				} else {
					logSink("RELOAD: rebound to iface=%q", newCfg.Interface)
				}
			}
			if oldAuth != newAuth {
				logSink("RELOAD: authoritative %v -> %v", oldAuth, newAuth)
			} else {
				logSink("RELOAD: authoritative=%v", newAuth)
			}
			logSink("RELOAD: config applied")

			// DETECT announcement after manual reload
			logDetect(&newCfg, currentIface, logSink)

		case syscall.SIGINT, syscall.SIGTERM:
			logSink("SIGNAL received, shutting down")
			_ = s.Close()
			_ = db.Save()
			if watcher != nil {
				_ = watcher.Close()
			}
			return nil
		}
	}
	return nil
}

/* ----------------- Watcher ----------------- */

// startConfigWatcher watches cfgPath and reservations file, calls onApply(validatedCfg,reservations,warns) after successful parses.
// It also performs the first_seen stamping persist just like the HUP path.
func startConfigWatcher(
	cfgPath string,
	reservationsPath string,
	onApply func(config.Config, config.Reservations, []string),
	logf func(string, ...any),
) (*fsnotify.Watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(cfgPath)
	if err := w.Add(dir); err != nil {
		_ = w.Close()
		return nil, err
	}
	// Also watch reservations file directory if different
	if reservationsPath != "" && filepath.Dir(reservationsPath) != dir {
		reservationsDir := filepath.Dir(reservationsPath)
		if err := w.Add(reservationsDir); err != nil {
			_ = w.Close()
			return nil, err
		}
	}
	go func() {
		for {
			select {
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				evName := filepath.Clean(ev.Name)
				cfgPathClean := filepath.Clean(cfgPath)
				reservationsPathClean := ""
				if reservationsPath != "" {
					reservationsPathClean = filepath.Clean(reservationsPath)
				}
				// Watch both config and reservations file
				if evName != cfgPathClean && evName != reservationsPathClean {
					continue
				}
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Chmod) == 0 {
					continue
				}
				time.Sleep(150 * time.Millisecond)

				// Reload config and reservations
				cfgNew, reservationsNew, reservationsPathNew, jerr := config.ParseStrict(cfgPath)
				if jerr != nil {
					logf("AUTO-RELOAD: config invalid, keeping old settings: %v", jerr)
					continue
				}

				now := time.Now().Unix()
				reservationsChanged := false
				for k, v := range reservationsNew {
					if v.FirstSeen == 0 {
						v.FirstSeen = now
						reservationsNew[k] = v
						reservationsChanged = true
					}
				}
				if cfgNew.BannedMACs == nil {
					cfgNew.BannedMACs = make(map[string]config.DeviceMeta)
				}
				bannedChanged := false
				for k, v := range cfgNew.BannedMACs {
					if v.FirstSeen == 0 {
						v.FirstSeen = now
						cfgNew.BannedMACs[k] = v
						bannedChanged = true
					}
				}
				if reservationsChanged {
					// Save reservations to separate file
					if err := config.SaveReservations(reservationsPathNew, reservationsNew); err != nil {
						logf("AUTO-RELOAD: failed to persist reservations first_seen: %v", err)
					}
				}
				if bannedChanged {
					// Save banned MACs back to config file
					tmp := cfgPath + ".tmp"
					if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err == nil {
						if f, err := os.Create(tmp); err == nil {
							enc := json.NewEncoder(f)
							enc.SetIndent("", "  ")
							if err := enc.Encode(&cfgNew); err == nil {
								_ = f.Sync()
								_ = f.Close()
								_ = os.Rename(tmp, cfgPath)
							} else {
								_ = f.Close()
								_ = os.Remove(tmp)
								logf("AUTO-RELOAD: failed to persist banned_macs first_seen: %v", err)
							}
						}
					}
				}

				norm, warns, verr := config.ValidateAndNormalizeConfig(cfgNew)
				if verr != nil {
					logf("AUTO-RELOAD: validation failed, keeping old settings: %v", verr)
					continue
				}

				onApply(norm, reservationsNew, warns)

			case err := <-w.Errors:
				logf("watcher error: %v", err)
			}
		}
	}()
	return w, nil
}

/* ----------------- Stats helpers ----------------- */

func loadDBAndConfig(cfgPath string) (*dhcpserver.LeaseDB, config.Config, config.Reservations, error) {
	raw, reservations, _, jerr := config.ParseStrict(cfgPath)
	if jerr != nil {
		return nil, config.Config{}, nil, jerr
	}
	cfg, _, verr := config.ValidateAndNormalizeConfig(raw)
	if verr != nil {
		return nil, config.Config{}, nil, verr
	}
	db := dhcpserver.NewLeaseDB(cfg.LeaseDBPath)
	if err := db.Load(); err != nil {
		return nil, config.Config{}, nil, err
	}
	return db, cfg, reservations, nil
}

/* ----------------- Cobra CLI ----------------- */

func addConsoleCommands(root *cobra.Command) {
	var socket string
	var tcpAddr string
	var transparent bool

	consoleCmd := &cobra.Command{
		Use:   "console",
		Short: "Console-related commands",
	}

	attachCmd := &cobra.Command{
		Use:   "attach",
		Short: "Attach to the running console via UNIX socket or TCP",
		RunE: func(_ *cobra.Command, _ []string) error {
			opts := planeconsole.AttachOptions{
				Transparent:       transparent,
				Title:             "DHCPlane Console (attached)",
				DisconnectMessage: "[notice] disconnected from server",
				OnExit: func(code int) {
					go func() {
						time.Sleep(25 * time.Millisecond)
						os.Exit(code)
					}()
				},
			}

			if tcpAddr != "" {
				// Connect via TCP using SocketResolver
				opts.SocketResolver = func() (string, error) {
					return tcpAddr, nil
				}
			} else {
				// Default: UNIX socket
				opts.Socket = socket
				opts.SocketCandidates = consoleSocketCandidates()
			}

			return planeconsole.Attach(opts)
		},
	}
	attachCmd.Flags().StringVar(&socket, "socket", "", "UNIX socket path override")
	attachCmd.Flags().StringVar(&tcpAddr, "tcp", "", "TCP address to connect to (e.g., 192.168.1.2:9090 or localhost:9090)")
	attachCmd.Flags().BoolVar(&transparent, "transparent", false, "Use terminal background")

	consoleCmd.AddCommand(attachCmd)
	root.AddCommand(consoleCmd)
}

func main() {
	var (
		cfgPath     string
		console     bool
		showVersion bool
	)

	root := &cobra.Command{
		Use:   "dhcplane",
		Short: "DHCPv4 server (insomniacslk/dhcp) with JSON config, reservations (with notes), logging, sticky leases, stats, and live reload",
	}
	root.PersistentFlags().BoolVarP(&showVersion, "version", "", false, "Print version and exit")
	root.PersistentFlags().StringVarP(&cfgPath, "config", "", "dhcplane.config", "Path to config file")
	// authoritative is now config-driven; flag removed
	root.PersistentFlags().BoolVar(&console, "console", false, "Export console over UNIX socket (or TCP if console_tcp_address is set) in addition to stdout/stderr logging")
	
	// Migrate old config filename if needed
	root.PersistentPreRunE = func(_ *cobra.Command, _ []string) error {
		if showVersion {
			fmt.Println(appVersion)
			os.Exit(0)
		}
		// Migrate old config filename before any command runs
		if err := migrateConfigFilename(cfgPath); err != nil {
			return err
		}
		// Also check for config file conflicts (both old and new exist)
		// This is handled in migrateConfigFilename, but we also want to check
		// reservations file if config exists
		if _, err := os.Stat(cfgPath); err == nil {
			// Config exists, check for reservations file migration
			cfgDir := filepath.Dir(cfgPath)
			if cfgDir == "." {
				cfgDir, _ = os.Getwd()
			}
			reservationsPath := filepath.Join(cfgDir, "dhcplane.reservations")
			checkReservationsFileMigration(reservationsPath)
		}
		return nil
	}

	// Inject the client-side attach command into this binary.
	addConsoleCommands(root)

	/* ---- serve ---- */
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the DHCP server",
		RunE: func(_ *cobra.Command, _ []string) error {
			// Create a default config if missing
			if err := ensureDefaultConfig(cfgPath); err != nil {
				return fmt.Errorf("default config: %w", err)
			}

			// Validate config before start
			if _, _, _, jerr := config.ParseStrict(cfgPath); jerr != nil {
				return fmt.Errorf("config error: %w", jerr)
			}

			return buildServerAndRun(cfgPath, console)
		},
	}

	/* ---- leases ---- */
	var jsonOut bool
	showCmd := &cobra.Command{
		Use:   "leases",
		Short: "Print current leases",
		RunE: func(_ *cobra.Command, _ []string) error {
			db, _, _, err := loadDBAndConfig(cfgPath)
			if err != nil {
				return err
			}

			type row struct {
				IP          string `json:"ip"`
				MAC         string `json:"mac"`
				Hostname    string `json:"hostname"`
				AllocatedAt string `json:"allocated_at"`
				Expiry      string `json:"expiry"`
				FirstSeen   string `json:"first_seen"`
			}
			var rows []row
			db.ForEach(func(l dhcpserver.Lease) {
				rows = append(rows, row{
					IP:          l.IP,
					MAC:         l.MAC,
					Hostname:    l.Hostname,
					AllocatedAt: dhcpserver.FormatEpoch(l.AllocatedAt),
					Expiry:      dhcpserver.FormatEpoch(l.Expiry),
					FirstSeen:   dhcpserver.FormatEpoch(l.FirstSeen),
				})
			})
			// Keep stable order by IP
			sort.Slice(rows, func(i, j int) bool {
				return ipKey(rows[i].IP) < ipKey(rows[j].IP)
			})

			if jsonOut {
				b, _ := json.MarshalIndent(rows, "", "  ")
				fmt.Println(string(b))
				return nil
			}

			// tabular default
			w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
			fmt.Fprintln(w, "IP\tMAC\tHostname\tAllocatedAt\tExpiry\tFirstSeen")
			for _, r := range rows {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					r.IP, r.MAC, r.Hostname, r.AllocatedAt, r.Expiry, r.FirstSeen)
			}
			w.Flush()
			return nil
		},
	}
	showCmd.Flags().BoolVar(&jsonOut, "json", false, "Output leases in JSON")

	/* ---- stats ---- */
	var details bool
	var grid bool
	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Show allocation rates and lease status (add --details for a full table, --grid for a colour grid)",
		RunE: func(_ *cobra.Command, _ []string) error {
			db, cfg, reservations, err := loadDBAndConfig(cfgPath)
			if err != nil {
				return err
			}
			assume := time.Duration(cfg.LeaseSeconds) * time.Second
			now := time.Now()

			// Build banned MAC set (merge config + env)
			bannedSet := make(map[string]struct{})
			for m := range cfg.BannedMACs {
				if nm, err := dhcpserver.CanonMAC(m); err == nil {
					bannedSet[nm] = struct{}{}
				} else {
					nm = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(m), "-", ":"), " ", ""))
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

			// Live iteration over leases without copying
			iter := func(yield func(statistics.LeaseLite)) {
				db.ForEach(func(l dhcpserver.Lease) {
					yield(statistics.LeaseLite{
						IP:          l.IP,
						MAC:         l.MAC,
						Hostname:    l.Hostname,
						AllocatedAt: l.AllocatedAt,
						Expiry:      l.Expiry,
					})
				})
			}
			isDeclined := func(ip string) bool { return db.IsDeclined(ip) }

			perMinute, perHour, perDay, perWeek, perMonth := statistics.CountAllocations(iter, assume, now)
			curr, expiring, expired := statistics.ClassifyLeases(iter, assume, now)

			fmt.Printf("Allocations: last 1m=%d  1h=%d  24h=%d  7d=%d  30d=%d\n",
				perMinute, perHour, perDay, perWeek, perMonth)
			fmt.Printf("Leases: current=%d  expiring=%d  expired=%d\n",
				len(curr), len(expiring), len(expired))

			if details {
				rows, err := statistics.BuildDetailRows(cfg, reservations, iter, isDeclined, isBanned, now)
				if err != nil {
					return err
				}
				statistics.PrintDetailsTable("DETAILS (entire subnet)", rows, assume, now)
			}

			if grid {
				if err := statistics.DrawSubnetGrid(cfg, reservations, iter, isDeclined, isBanned, 25, now); err != nil {
					return err
				}
			}
			return nil
		},
	}
	statsCmd.Flags().BoolVar(&details, "details", false, "Print a full table for the whole subnet including Type")
	statsCmd.Flags().BoolVar(&grid, "grid", false, "Render a full-subnet colour grid (green=free, red=leased, brown=reserved, light-gray=banned-mac, dark-gray=banned/excluded IPs)")

	/* ---- check ---- */
	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Validate the JSON config and exit (reports line/column on errors)",
		RunE: func(_ *cobra.Command, _ []string) error {
			_, _, _, jerr := config.ParseStrict(cfgPath)
			if jerr != nil {
				return jerr
			}
			fmt.Println("OK: config is valid")
			return nil
		},
	}

	/* ---- reload ---- */
	reloadCmd := &cobra.Command{
		Use:   "reload",
		Short: "Signal a running server to reload the config (SIGHUP via PID file)",
		RunE: func(_ *cobra.Command, _ []string) error {
			// Check file is valid before signaling
			raw, _, _, jerr := config.ParseStrict(cfgPath)
			if jerr != nil {
				return fmt.Errorf("refusing to reload: config invalid: %w", jerr)
			}
			cfg, _, verr := config.ValidateAndNormalizeConfig(raw)
			if verr != nil {
				return fmt.Errorf("refusing to reload: config invalid: %w", verr)
			}
			pid, err := readPID(cfg.PIDFile)
			if err != nil {
				return fmt.Errorf("read pid: %w", err)
			}
			if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
				return fmt.Errorf("signal: %w", err)
			}
			fmt.Printf("Sent SIGHUP to pid %d\n", pid)
			return nil
		},
	}

	/* ---- manage add/remove (with notes & conflict checks) ---- */
	manageCmd := &cobra.Command{
		Use:   "manage",
		Short: "Manage configuration (reservations, etc.)",
	}

	addCmd := &cobra.Command{
		Use:   "add <mac> <ip> [note...]",
		Short: "Add or update a MAC→IP reservation; optional note",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			norm, err := dhcpserver.CanonMAC(args[0])
			if err != nil {
				return errf("invalid mac: %v", err)
			}
			ip := net.ParseIP(args[1]).To4()
			if ip == nil {
				return errf("invalid IPv4: %s", args[1])
			}
			note := ""
			if len(args) > 2 {
				note = strings.TrimSpace(strings.Join(args[2:], " "))
			}

			rawCfg, reservations, _, jerr := config.ParseStrict(cfgPath)
			if jerr != nil {
				return jerr
			}
			cfg, _, verr := config.ValidateAndNormalizeConfig(rawCfg)
			if verr != nil {
				return verr
			}
			_, subnet := mustCIDR(cfg.SubnetCIDR)
			if !subnet.Contains(ip) {
				warnf("IP %s not in subnet %s", ip, cfg.SubnetCIDR)
			}

			// Conflict A: IP already reserved for someone else?
			for macKey, res := range reservations {
				if macEqual(macKey, norm) {
					continue
				}
				if res.IP == ip.String() {
					return errf("IP %s is already reserved for %s", ip.String(), macKey)
				}
			}

			// Conflict B: IP currently leased to a different MAC? (warn)
			leasePath := cfg.LeaseDBPath
			db := dhcpserver.NewLeaseDB(leasePath)
			_ = db.Load()
			if l, ok := db.FindByIP(ip.String()); ok && !macEqual(l.MAC, norm) {
				warnf("IP %s currently leased to %s (hostname=%q) until %s",
					ip.String(), l.MAC, l.Hostname, dhcpserver.FormatEpoch(l.Expiry))
			}

			// Upsert reservation with first_seen epoch
			if reservations == nil {
				reservations = make(config.Reservations)
			}
			now := time.Now().Unix()
			prev, existed := reservations[norm]
			if !existed {
				reservations[norm] = config.Reservation{
					IP:        ip.String(),
					Note:      note,
					FirstSeen: now,
				}
				fmt.Printf("Added reservation: %s -> %s  note=%q  first_seen=%s\n",
					norm, ip.String(), note, dhcpserver.FormatEpoch(now))
			} else {
				fs := prev.FirstSeen
				if fs == 0 {
					fs = now
				}
				reservations[norm] = config.Reservation{
					IP:                  ip.String(),
					Note:                note,
					FirstSeen:           fs,
					EquipmentType:       prev.EquipmentType,
					Manufacturer:        prev.Manufacturer,
					ManagementType:      prev.ManagementType,
					ManagementInterface: prev.ManagementInterface,
				}
				fmt.Printf("Updated reservation: %s  %s -> %s  note=%q (first_seen=%s)\n",
					norm, prev.IP, ip.String(), note, dhcpserver.FormatEpoch(fs))
			}

			// Write reservations to separate file
			_, _, reservationsPath, _ := config.ParseStrict(cfgPath)
			if err := config.SaveReservations(reservationsPath, reservations); err != nil {
				return err
			}
			return nil
		},
	}

	removeCmd := &cobra.Command{
		Use:   "remove <mac>",
		Short: "Remove a MAC→IP reservation (and note) from the config",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			norm, err := dhcpserver.CanonMAC(args[0])
			if err != nil {
				return errf("invalid mac: %v", err)
			}
			_, reservations, _, jerr := config.ParseStrict(cfgPath)
			if jerr != nil {
				return jerr
			}
			if reservations == nil {
				fmt.Println("Nothing to remove: no reservations")
				return nil
			}
			if _, ok := reservations[norm]; !ok {
				fmt.Printf("No reservation for %s\n", norm)
				return nil
			}
			delete(reservations, norm)

			// Write reservations to separate file
			_, _, reservationsPath, _ := config.ParseStrict(cfgPath)
			if err := config.SaveReservations(reservationsPath, reservations); err != nil {
				return err
			}
			fmt.Printf("Reservation removed: %s in %s\n", norm, reservationsPath)
			return nil
		},
	}

	manageCmd.AddCommand(addCmd, removeCmd)

	var arpAllIfaces bool
	var arpJSON bool
	var arpRefresh bool
	var arpIface string
	arpCmd := &cobra.Command{
		Use:   "arp",
		Short: "Scan/read ARP and print a table; Linux scans, macOS/Windows read cache",
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, reservations := cfgGetForCLI(cfgPath) // keep your helper
			if !arpAllIfaces && cfg.Interface != "" && arpIface == "" {
				arpIface = cfg.Interface
			}

			entries, _, err := arp.ScanForCLI(cfg, reservations, cfg.LeaseDBPath, arpIface, arpAllIfaces, arpRefresh, time.Second*3)
			if err != nil {
				return err
			}

			// numeric IPv4 sort with iface tie-breaker
			sort.Slice(entries, func(i, j int) bool {
				ki, kj := ipKey(entries[i].IP), ipKey(entries[j].IP)
				if ki == kj {
					return entries[i].Iface < entries[j].Iface
				}
				return ki < kj
			})

			if arpJSON {
				b, _ := json.MarshalIndent(entries, "", "  ")
				fmt.Println(string(b))
				return nil
			}
			arp.PrintTable(entries)
			return nil
		},
	}
	arpCmd.Flags().BoolVar(&arpAllIfaces, "all-ifaces", false, "Use all interfaces")
	arpCmd.Flags().BoolVar(&arpJSON, "json", false, "JSON output")
	arpCmd.Flags().BoolVar(&arpRefresh, "refresh", false, "Best-effort cache warm-up on macOS/Windows")
	arpCmd.Flags().StringVar(&arpIface, "iface", "", "Interface name override")

	searchCmd := &cobra.Command{
		Use:   "search <ip>",
		Short: "Search for an IP address in reservations and leases",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			ipStr := args[0]
			ip := net.ParseIP(ipStr).To4()
			if ip == nil {
				return errf("invalid IPv4 address: %s", ipStr)
			}

			db, cfg, reservations, err := loadDBAndConfig(cfgPath)
			if err != nil {
				return err
			}

			found := false
			fmt.Println(aurora.Bold(fmt.Sprintf("Search results for %s:", ipStr)))
			fmt.Println()

			// Check reservations
			var resMAC string
			var reservation config.Reservation
			for mac, res := range reservations {
				if res.IP == ipStr {
					found = true
					resMAC = mac
					reservation = res
					break
				}
			}

			if resMAC != "" {
				fmt.Println(aurora.Green("✓ RESERVATION FOUND"))
				fmt.Printf("  MAC Address: %s\n", aurora.Bold(resMAC))
				if reservation.Note != "" {
					fmt.Printf("  Note: %s\n", reservation.Note)
				}
				if reservation.EquipmentType != "" {
					fmt.Printf("  Equipment Type: %s\n", reservation.EquipmentType)
				}
				if reservation.Manufacturer != "" {
					fmt.Printf("  Manufacturer: %s\n", reservation.Manufacturer)
				}
				if reservation.ManagementType != "" {
					fmt.Printf("  Management Type: %s\n", reservation.ManagementType)
				}
				if reservation.ManagementInterface != "" {
					fmt.Printf("  Management Interface: %s\n", reservation.ManagementInterface)
				}
				if reservation.FirstSeen > 0 {
					firstSeen := time.Unix(reservation.FirstSeen, 0).Local()
					fmt.Printf("  First Seen: %s\n", firstSeen.Format("2006-01-02 15:04:05 MST"))
				}
				fmt.Println()
			} else {
				fmt.Println(aurora.Yellow("✗ Not in reservations"))
				fmt.Println()
			}

			// Check leases
			if lease, ok := db.FindByIP(ipStr); ok {
				found = true
				fmt.Println(aurora.Green("✓ LEASE FOUND"))
				fmt.Printf("  MAC Address: %s\n", aurora.Bold(lease.MAC))
				if lease.Hostname != "" {
					fmt.Printf("  Hostname: %s\n", lease.Hostname)
				}
				if lease.AllocatedAt > 0 {
					allocated := time.Unix(lease.AllocatedAt, 0).Local()
					fmt.Printf("  Allocated At: %s\n", allocated.Format("2006-01-02 15:04:05 MST"))
				}
				if lease.Expiry > 0 {
					expiry := time.Unix(lease.Expiry, 0).Local()
					now := time.Now()
					if now.After(expiry) {
						fmt.Printf("  Expiry: %s %s\n", expiry.Format("2006-01-02 15:04:05 MST"), aurora.Red("(EXPIRED)"))
					} else {
						remaining := expiry.Sub(now)
						fmt.Printf("  Expiry: %s %s\n", expiry.Format("2006-01-02 15:04:05 MST"), aurora.Green(fmt.Sprintf("(expires in %s)", formatDuration(remaining))))
					}
				} else {
					fmt.Printf("  Expiry: %s\n", aurora.Yellow("No expiry set"))
				}
				if lease.FirstSeen > 0 {
					firstSeen := time.Unix(lease.FirstSeen, 0).Local()
					fmt.Printf("  First Seen: %s\n", firstSeen.Format("2006-01-02 15:04:05 MST"))
				}
				fmt.Println()
			} else {
				fmt.Println(aurora.Yellow("✗ Not in leases"))
				fmt.Println()
			}

			// Check if MAC matches between reservation and lease
			if resMAC != "" {
				if lease, ok := db.FindByIP(ipStr); ok {
					if !macEqual(resMAC, lease.MAC) {
						fmt.Println(aurora.Red("⚠ WARNING: MAC address mismatch!"))
						fmt.Printf("  Reservation MAC: %s\n", resMAC)
						fmt.Printf("  Lease MAC: %s\n", lease.MAC)
						fmt.Println()
					} else {
						fmt.Println(aurora.Green("✓ MAC addresses match between reservation and lease"))
						fmt.Println()
					}
				}
			}

			if !found {
				fmt.Println(aurora.Red("✗ IP address not found in reservations or leases"))
				fmt.Println()
				fmt.Println(aurora.Yellow("Suggestion: Try running an ARP scan to see if this IP is active on the network:"))
				if cfg.Interface != "" {
					fmt.Printf("  %s arp --iface %s\n", os.Args[0], cfg.Interface)
				} else {
					fmt.Printf("  %s arp\n", os.Args[0])
				}
			}

			return nil
		},
	}

	root.AddCommand(serveCmd, showCmd, statsCmd, checkCmd, reloadCmd, manageCmd, arpCmd, searchCmd)
	if err := root.Execute(); err != nil {
		log.Fatal(err)
	}
}

func triggerARPScan(
	cfgGet func() *config.Config,
	reservationsGet func() config.Reservations,
	db *dhcpserver.LeaseDB,
	iface string,
	logf, errf func(string, ...any),
	_ bool, // allIfaces currently unused here; keep for future
) {
	cfg := cfgGet()
	reservations := reservationsGet()
	entries, findings, err := arp.Scan(cfg, reservations, db, iface, false, time.Second*3)
	if err != nil {
		errf("ARP scan error: %v", err)
		return
	}
	_ = entries // reserved for future use
	for _, f := range findings {
		// Build log message with conditional MAC fields
		msg := fmt.Sprintf("ARP-ANOMALY ip=%s mac=%s iface=%s reason=%s found=%s reserved=%t leased=%t excluded=%t",
			f.IP, f.MAC, f.Iface, f.Reason, f.Found, f.Reserved, f.Leased, f.Excluded)
		if f.Leased && f.LeaseMAC != "" {
			msg += fmt.Sprintf(" lease_mac=%s", f.LeaseMAC)
		}
		if f.Reserved && f.ResMAC != "" {
			msg += fmt.Sprintf(" res_mac=%s", f.ResMAC)
		}
		logf("%s", msg)
	}
}

// triggerDHCPServerScan detects rogue DHCP servers by sending a DISCOVER and listening for responses.
func triggerDHCPServerScan(
	cfgGet func() *config.Config,
	iface string,
	logf, errf func(string, ...any),
) {
	cfg := cfgGet()
	if !cfg.DetectDHCPServers.Enabled {
		return
	}

	serverIP := net.ParseIP(cfg.ServerIP).To4()
	if serverIP == nil {
		errf("DHCP server detection: invalid server_ip %s", cfg.ServerIP)
		return
	}

	// Build whitelist set
	whitelist := make(map[string]bool)
	whitelist[serverIP.String()] = true // Our own server is always whitelisted
	for _, w := range cfg.DetectDHCPServers.WhitelistServers {
		whitelist[w] = true
	}

	// Create a temporary MAC for the probe
	probeMAC, err := net.ParseMAC("00:00:00:00:00:00")
	if err != nil {
		errf("DHCP server detection: failed to create probe MAC: %v", err)
		return
	}

	// Create DISCOVER packet
	discover, err := dhcpv4.NewDiscovery(probeMAC)
	if err != nil {
		errf("DHCP server detection: failed to create DISCOVER: %v", err)
		return
	}
	discover.SetBroadcast()

	// Set up listener on a separate socket to catch responses
	conn, err := net.ListenPacket("udp4", ":68")
	if err != nil {
		errf("DHCP server detection: failed to listen on UDP 68: %v", err)
		return
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Send DISCOVER
	var destAddr *net.UDPAddr
	if iface != "" {
		// Try to get broadcast address for the interface
		ifi, err := net.InterfaceByName(iface)
		if err == nil {
			addrs, _ := ifi.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					ip := ipnet.IP.To4()
					mask := ipnet.Mask
					broadcast := make(net.IP, 4)
					for i := 0; i < 4; i++ {
						broadcast[i] = ip[i] | ^mask[i]
					}
					destAddr = &net.UDPAddr{IP: broadcast, Port: 67}
					break
				}
			}
		}
	}
	if destAddr == nil {
		destAddr = &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
	}

	if _, err := conn.WriteTo(discover.ToBytes(), destAddr); err != nil {
		errf("DHCP server detection: failed to send DISCOVER: %v", err)
		return
	}

	logf("DETECT scan started iface=%s", iface)

	// Listen for OFFER responses
	seenServers := make(map[string]bool)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 1500)
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			break
		}

		resp, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			continue
		}

		// Only process OFFER messages
		if resp.MessageType() != dhcpv4.MessageTypeOffer {
			continue
		}

		// Get server identifier
		serverIDOpt := resp.Options.Get(dhcpv4.OptionServerIdentifier)
		if len(serverIDOpt) != 4 {
			continue
		}
		serverID := net.IP(serverIDOpt).To4().String()

		// Skip if already seen or whitelisted
		if seenServers[serverID] || whitelist[serverID] {
			continue
		}
		seenServers[serverID] = true

		// Check if it's our server
		if serverID == serverIP.String() {
			continue
		}

		// Log foreign DHCP server
		peerIP := "unknown"
		if peerAddr, ok := peer.(*net.UDPAddr); ok {
			peerIP = peerAddr.IP.String()
		}
		logf("FOREIGN-DHCP-SERVER detected server_ip=%s from=%s iface=%s", serverID, peerIP, iface)
	}

	// Log completion
	if len(seenServers) == 0 {
		logf("DETECT scan completed iface=%s (no foreign servers found)", iface)
	} else {
		logf("DETECT scan completed iface=%s (found %d server(s))", iface, len(seenServers))
	}
}

func cfgGetForCLI(cfgPath string) (config.Config, config.Reservations) {
	raw, reservations, _, _ := config.ParseStrict(cfgPath)
	cfg, _, _ := config.ValidateAndNormalizeConfig(raw)
	return cfg, reservations
}

/* ----------------- Small helpers kept in main ----------------- */

// migrateConfigFilename migrates old config filename (dhcplane.json) to new format (dhcplane.config).
// If the requested config path doesn't exist but the old filename does in the same directory,
// it attempts to rename it. If rename fails, exits with a red error message.
// If both old and new files exist, shows a yellow warning.
func migrateConfigFilename(cfgPath string) error {
	cfgDir := filepath.Dir(cfgPath)
	cfgBase := filepath.Base(cfgPath)
	
	if cfgDir == "." {
		cfgDir, _ = os.Getwd()
	}
	
	// Determine old and new paths
	var oldPath, newPath string
	if cfgBase == "dhcplane.config" || cfgBase == "dhcplane.json" {
		oldPath = filepath.Join(cfgDir, "dhcplane.json")
		newPath = filepath.Join(cfgDir, "dhcplane.config")
	} else if strings.HasSuffix(cfgBase, ".config") {
		oldBase := strings.TrimSuffix(cfgBase, ".config") + ".json"
		oldPath = filepath.Join(cfgDir, oldBase)
		newPath = cfgPath
	} else if strings.HasSuffix(cfgBase, ".json") {
		newBase := strings.TrimSuffix(cfgBase, ".json") + ".config"
		oldPath = cfgPath
		newPath = filepath.Join(cfgDir, newBase)
	} else {
		return nil // Not a config file pattern
	}
	
	oldExists := false
	newExists := false
	if _, err := os.Stat(oldPath); err == nil {
		oldExists = true
	}
	if _, err := os.Stat(newPath); err == nil {
		newExists = true
	}
	
	if oldExists && newExists {
		// Both exist, warn in yellow
		fmt.Fprintln(os.Stderr, aurora.Yellow(fmt.Sprintf("WARNING: Both old config file (%s) and new config file (%s) exist. Using new file.", oldPath, newPath)))
		return nil
	}
	
	if oldExists && !newExists {
		// Old exists, new doesn't - migrate
		if err := os.Rename(oldPath, newPath); err != nil {
			fmt.Fprintln(os.Stderr, aurora.Red(fmt.Sprintf("ERROR: Failed to migrate config file from %s to %s: %v", oldPath, newPath, err)))
			fmt.Fprintln(os.Stderr, aurora.Red("Please manually rename the file or fix the permissions and try again."))
			os.Exit(1)
		}
	}
	
	return nil
}

// migrateLeasesFile migrates old leases filename (leases.json) to new format (dhcplane.leases).
// If both old and new files exist, shows a yellow warning.
func migrateLeasesFile(leasePath string) error {
	leaseDir := filepath.Dir(leasePath)
	leaseBase := filepath.Base(leasePath)
	
	if leaseDir == "." {
		leaseDir, _ = os.Getwd()
	}
	
	// Determine old and new paths
	var oldPath, newPath string
	if leaseBase == "dhcplane.leases" || leaseBase == "leases.json" {
		oldPath = filepath.Join(leaseDir, "leases.json")
		newPath = filepath.Join(leaseDir, "dhcplane.leases")
	} else {
		return nil // Custom path, no migration
	}
	
	oldExists := false
	newExists := false
	if _, err := os.Stat(oldPath); err == nil {
		oldExists = true
	}
	if _, err := os.Stat(newPath); err == nil {
		newExists = true
	}
	
	if oldExists && newExists {
		// Both exist, warn in yellow
		fmt.Fprintln(os.Stderr, aurora.Yellow(fmt.Sprintf("WARNING: Both old leases file (%s) and new leases file (%s) exist. Using new file.", oldPath, newPath)))
		return nil
	}
	
	if oldExists && !newExists {
		// Old exists, new doesn't - migrate
		if err := os.Rename(oldPath, newPath); err != nil {
			fmt.Fprintln(os.Stderr, aurora.Red(fmt.Sprintf("ERROR: Failed to migrate leases file from %s to %s: %v", oldPath, newPath, err)))
			fmt.Fprintln(os.Stderr, aurora.Red("Please manually rename the file or fix the permissions and try again."))
			os.Exit(1)
		}
	}
	
	return nil
}

// checkReservationsFileMigration checks for old reservations file format and warns if both exist.
func checkReservationsFileMigration(reservationsPath string) {
	reservationsDir := filepath.Dir(reservationsPath)
	
	if reservationsDir == "." {
		reservationsDir, _ = os.Getwd()
	}
	
	// Check for old format - reservations.json (if someone manually created it)
	oldPath := filepath.Join(reservationsDir, "reservations.json")
	newPath := reservationsPath
	
	oldExists := false
	newExists := false
	if _, err := os.Stat(oldPath); err == nil {
		oldExists = true
	}
	if _, err := os.Stat(newPath); err == nil {
		newExists = true
	}
	
	if oldExists && newExists {
		// Both exist, warn in yellow
		fmt.Fprintln(os.Stderr, aurora.Yellow(fmt.Sprintf("WARNING: Both old reservations file (%s) and new reservations file (%s) exist. Using new file.", oldPath, newPath)))
	}
}

func errf(format string, a ...any) error {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, aurora.Red(fmt.Sprintf("ERROR: %s", msg)))
	return fmt.Errorf("%s", msg)
}

func warnf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, aurora.Yellow(fmt.Sprintf("WARNING: %s", msg)))
}

// formatDuration formats a duration in a human-readable way (e.g., "2h30m15s").
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % 60
		if seconds > 0 {
			return fmt.Sprintf("%dm%ds", minutes, seconds)
		}
		return fmt.Sprintf("%dm", minutes)
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	if minutes > 0 {
		return fmt.Sprintf("%dh%dm", hours, minutes)
	}
	return fmt.Sprintf("%dh", hours)
}

func mustCIDR(c string) (net.IP, *net.IPNet) {
	ip, n, err := net.ParseCIDR(c)
	if err != nil {
		log.Fatalf("bad subnet_cidr %q: %v", c, err)
	}
	return ip, n
}

// macEqual normalizes both sides and compares.
func macEqual(a, b string) bool {
	na, ea := dhcpserver.CanonMAC(a)
	nb, eb := dhcpserver.CanonMAC(b)
	if ea == nil && eb == nil {
		return na == nb
	}
	return strings.EqualFold(a, b)
}

// ensureDefaultConfig writes a sane default config if cfgPath does not exist.
func ensureDefaultConfig(cfgPath string) error {
	_, err := os.Stat(cfgPath)
	if err == nil {
		return nil // exists
	}
	if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil && !os.IsExist(err) {
		return err
	}

	// Default: 192.168.1.0/24
	def := map[string]any{
		"interface":                "",
		"server_ip":                "192.168.1.2",
		"subnet_cidr":              "192.168.1.0/24",
		"gateway":                  "192.168.1.1",
		"compact_on_load":          false,
		"dns":                      []string{"192.168.1.1", "1.1.1.1"},
		"domain":                   "lan",
		"lease_db_path":            "dhcplane.leases",
		"pid_file":                 "dhcplane.pid",
		"authoritative":            true, // default authoritative if unset
		"lease_seconds":            86400, // 24h
		"lease_sticky_seconds":     86400, // default sticky window
		"auto_reload":              true,
		"pools":                    []map[string]string{{"start": "192.168.1.100", "end": "192.168.1.200"}},
		"exclusions":               []string{"192.168.1.1", "192.168.1.2"},
		"reservations_path":        "dhcplane.reservations",
		"ntp":                      []string{},
		"mtu":                      0,
		"tftp_server_name":         "", // opt 66
		"bootfile_name":            "", // opt 67
		"wpad_url":                 "",
		"wins":                     []string{},
		"domain_search":            []string{},
		"static_routes":            []map[string]string{},
		"mirror_routes_to_249":     false,
		"vendor_specific_43_hex":   "", // opt 43 (hex payload)
		"device_overrides":         map[string]any{},
		"vendor_class_overrides":   map[string]any{}, // Vendor Class overrides (by option 60 string)
		"user_class_overrides_77":  map[string]any{},
		"hostname_12":              "", // suggest hostname (opt 12) when client does not supply one
		"enable_broadcast_28":      false,
		"use_classful_routes_33":   false,
		"routes_33":                []map[string]string{}, // {"destination":"a.b.c.0","gateway":"x.y.z.w"}
		"netbios_node_type_46":     0,                     // 0 omit, else {1,2,4,8}
		"netbios_scope_id_47":      "",
		"max_dhcp_message_size_57": 0,          // 0 omit, else >=576
		"tftp_servers_150":         []string{}, // list of IPv4s
		"echo_relay_agent_info_82": false,
		"banned_macs":              map[string]any{},
		"equipment_types":          []string{"Switch", "Router", "AP", "Modem", "Gateway"},
		"management_types":         []string{"ssh", "web", "telnet", "serial", "console"},
		"console_max_lines":        10000,
		"console_tcp_address":      "", // empty = UNIX socket; e.g., "0.0.0.0:9090" for TCP
		"logging": map[string]any{
			"path":        "",
			"filename":    "dhcplane.log",
			"max_size":    20, // MB
			"max_backups": 5,
			"max_age":     0,    // days; 0 = no age-based purge
			"compress":    true, // gzip (lumberjack)
		},
		"detect_dhcp_servers": map[string]any{
			"enabled":           true,
			"active_probe":      "off",   // off|safe|aggressive
			"probe_interval":    600,     // seconds
			"first_scan":        60,      // seconds, default 60
			"rate_limit":        6,       // events per minute per server
			"whitelist_servers": []any{}, // IPv4 or MAC entries
		},
		"arp_anomaly_detection": map[string]any{
			"enabled":        false,
			"probe_interval": 1800, // seconds, default 1800
			"first_scan":     60,   // seconds, default 60
		},
	}

	b, _ := json.MarshalIndent(def, "", "  ")
	return os.WriteFile(cfgPath, b, 0o644)
}

/* ----------------- Local type needed for bind closer ----------------- */

type ioCloser interface {
	Close() error
}

func ipKey(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return ^uint32(0)
	}
	return dhcpserver.IPToU32(ip)
}
