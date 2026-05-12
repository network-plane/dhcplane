// Package config holds the JSON-config-related data types and logic
package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

/* ----------------- Config & Types ----------------- */

// Pool represents a range of IP addresses.
type Pool struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// StaticRoute represents a static route configuration.
type StaticRoute struct {
	CIDR    string `json:"cidr"`
	Gateway string `json:"gateway"`
}

// DeviceOverride represents per-device DHCP options.
type DeviceOverride struct {
	DNS            []string `json:"dns,omitempty"`              // opt 6
	TFTPServerName string   `json:"tftp_server_name,omitempty"` // opt 66
	BootFileName   string   `json:"bootfile_name,omitempty"`    // opt 67
}

// DeviceMeta contains metadata for a device.
type DeviceMeta struct {
	FirstSeen           int64  `json:"first_seen,omitempty"` // epoch seconds
	Note                string `json:"note,omitempty"`
	EquipmentType       string `json:"equipment_type,omitempty"`
	Manufacturer        string `json:"manufacturer,omitempty"`
	ManagementType      string `json:"management_type,omitempty"`
	ManagementInterface string `json:"management_interface,omitempty"`
}

// Reservation represents a DHCP reservation.
type Reservation struct {
	IP                  string `json:"ip"`
	Note                string `json:"note,omitempty"`
	FirstSeen           int64  `json:"first_seen,omitempty"` // epoch seconds
	EquipmentType       string `json:"equipment_type,omitempty"`
	Manufacturer        string `json:"manufacturer,omitempty"`
	ManagementType      string `json:"management_type,omitempty"`
	ManagementInterface string `json:"management_interface,omitempty"`
}

// Reservations is a map of MAC addresses to their DHCP reservations.
type Reservations map[string]Reservation

// UnmarshalJSON implements json.Unmarshaler.
func (r *Reservations) UnmarshalJSON(b []byte) error {
	// Try the new format first
	type newFormat map[string]Reservation
	var nf newFormat
	if err := json.Unmarshal(b, &nf); err == nil {
		*r = Reservations(nf)
		return nil
	}
	// Fallback to old format
	type oldFormat map[string]string
	var of oldFormat
	if err := json.Unmarshal(b, &of); err != nil {
		return err
	}
	out := make(Reservations, len(of))
	for k, v := range of {
		out[k] = Reservation{IP: v}
	}
	*r = out
	return nil
}

// StaticRoute33 represents a classful route for DHCP option 33.
type StaticRoute33 struct {
	Destination string `json:"destination"` // dotted-quad network (classful: a.0.0.0 | a.b.0.0 | a.b.c.0)
	Gateway     string `json:"gateway"`     // IPv4
}

// config/config.go

// Config represents the DHCP server configuration.
type Config struct {
	// File paths - these appear at the top of the config file
	LeaseDBPath      string        `json:"lease_db_path,omitempty"`      // Path to leases file (dir or file)
	ReservationsPath string        `json:"reservations_path,omitempty"` // Path to reservations file (dir or file)
	Logging          LoggingConfig `json:"logging"`                     // Log file settings
	PIDFile          string        `json:"pid_file,omitempty"`          // Path to PID file

	// Core network settings
	Interface     string   `json:"interface,omitempty"`
	ServerIP      string   `json:"server_ip"`
	SubnetCIDR    string   `json:"subnet_cidr"`
	Gateway       string   `json:"gateway"`
	CompactOnLoad bool     `json:"compact_on_load"`
	DNS           []string `json:"dns"`
	Domain        string   `json:"domain,omitempty"`

	// Authoritative mode: when true, server sends NAKs on invalid requests.
	// Nil means "unset" and defaults to true.
	Authoritative *bool `json:"authoritative,omitempty"`

	LeaseSeconds       int  `json:"lease_seconds"`
	LeaseStickySeconds int  `json:"lease_sticky_seconds,omitempty"`
	AutoReload         bool `json:"auto_reload,omitempty"`

	Pools      []Pool   `json:"pools"`
	Exclusions []string `json:"exclusions,omitempty"`

	NTP            []string `json:"ntp,omitempty"`
	MTU            int      `json:"mtu,omitempty"`
	TFTPServerName string   `json:"tftp_server_name,omitempty"` // opt 66
	BootFileName   string   `json:"bootfile_name,omitempty"`    // opt 67
	WPADURL        string   `json:"wpad_url,omitempty"`
	WINS           []string `json:"wins,omitempty"`

	DomainSearch        []string                  `json:"domain_search,omitempty"`
	StaticRoutes        []StaticRoute             `json:"static_routes,omitempty"`
	MirrorRoutesTo249   bool                      `json:"mirror_routes_to_249,omitempty"`
	VendorSpecific43Hex string                    `json:"vendor_specific_43_hex,omitempty"` // opt 43 (hex payload)
	DeviceOverrides     map[string]DeviceOverride `json:"device_overrides,omitempty"`

	// suggest hostname (opt 12) when client does not supply one
	Hostname12 string `json:"hostname_12,omitempty"`

	// per Vendor Class Identifier (opt 60) overrides
	VendorClassOverrides map[string]DeviceOverride `json:"vendor_class_overrides,omitempty"`

	// per User Class (opt 77) overrides
	UserClassOverrides77 map[string]DeviceOverride `json:"user_class_overrides_77,omitempty"`

	EnableBroadcast28    bool            `json:"enable_broadcast_28,omitempty"`
	UseClassfulRoutes33  bool            `json:"use_classful_routes_33,omitempty"`
	Routes33             []StaticRoute33 `json:"routes_33,omitempty"`
	NetBIOSNodeType46    uint8           `json:"netbios_node_type_46,omitempty"`
	NetBIOSScopeID47     string          `json:"netbios_scope_id_47,omitempty"`
	MaxDHCPMessageSize57 uint16          `json:"max_dhcp_message_size_57,omitempty"`
	TFTPServers150       []string        `json:"tftp_servers_150,omitempty"`
	EchoRelayAgentInfo82 bool            `json:"echo_relay_agent_info_82,omitempty"`

	// Config-based banned MACs with metadata
	BannedMACs map[string]DeviceMeta `json:"banned_macs,omitempty"`

	// Allowed enumerations
	EquipmentTypes  []string `json:"equipment_types,omitempty"`
	ManagementTypes []string `json:"management_types,omitempty"`

	// Max console buffer
	ConsoleMaxLines int `json:"console_max_lines,omitempty"`

	// Console TCP address (e.g., "0.0.0.0:9090" or ":9090"); empty = UNIX socket only
	ConsoleTCPAddress string `json:"console_tcp_address,omitempty"`

	// REST API (optional; off by default). JSON keys align with dnsplane.
	API                  bool    `json:"api,omitempty"`
	APIPort              string  `json:"apiport,omitempty"`
	APIBind              string  `json:"api_bind,omitempty"`
	APIAuthToken         string  `json:"api_auth_token,omitempty"`
	APITLSCertFile       string  `json:"api_tls_cert,omitempty"`
	APITLSKeyFile        string  `json:"api_tls_key,omitempty"`
	APIRateLimitPerIP    float64 `json:"api_rate_limit_rps,omitempty"`
	APIRateLimitBurst    int     `json:"api_rate_limit_burst,omitempty"`

	// StatsDashboardEnabled serves GET /stats/dashboard, /stats/dashboard/data, and /stats/dashboard/ws.
	// JSON omitted defaults to enabled (see DashboardHTMLEnabled).
	StatsDashboardEnabled *bool `json:"stats_dashboard_enabled,omitempty"`

	DetectDHCPServers DHCPServerDetectionConfig `json:"detect_dhcp_servers,omitempty"`

	ARPAnomalyDetection ARPAnomalyDetectionConfig `json:"arp_anomaly_detection,omitempty"`
}

// ARPAnomalyDetectionConfig holds settings for ARP anomaly detection.
type ARPAnomalyDetectionConfig struct {
	Enabled       bool `json:"enabled,omitempty"`
	ProbeInterval int  `json:"probe_interval,omitempty"` // seconds, default 1800
	FirstScan     int  `json:"first_scan,omitempty"`     // seconds, default 60
}

// DHCPServerDetectionConfig holds settings for DHCP server detection.
type DHCPServerDetectionConfig struct {
	Enabled          bool     `json:"enabled,omitempty"`
	ActiveProbe      string   `json:"active_probe,omitempty"`
	ProbeInterval    int      `json:"probe_interval,omitempty"`
	FirstScan        int      `json:"first_scan,omitempty"`     // seconds, default 60
	WhitelistServers []string `json:"whitelist_servers,omitempty"`
	RateLimit        int      `json:"rate_limit,omitempty"`
}

// LoggingConfig represents log rotation settings.
type LoggingConfig struct {
	// LogFile is the full path to the log file. If this is set, Path/Filename are ignored.
	// If it's a directory, "dhcplane.log" is appended.
	LogFile    string `json:"log_file,omitempty"`
	Path       string `json:"path,omitempty"`     // Directory for log files (legacy, use log_file instead)
	Filename   string `json:"filename,omitempty"` // Log filename (legacy, use log_file instead)
	MaxSize    int    `json:"max_size,omitempty"` // megabytes
	MaxBackups int    `json:"max_backups,omitempty"`
	MaxAge     int    `json:"max_age,omitempty"` // days
	Compress   bool   `json:"compress,omitempty"`
}

// StatsDashboardHTMLEnabled reports whether HTML/WS dashboard routes are allowed (default true when unset).
func (c *Config) StatsDashboardHTMLEnabled() bool {
	if c == nil || c.StatsDashboardEnabled == nil {
		return true
	}
	return *c.StatsDashboardEnabled
}

/* ----------------- Config parsing & validation ----------------- */

// JSONErr represents a JSON parsing error with line/column info.
type JSONErr struct {
	Err    error
	Line   int
	Column int
}

func (e *JSONErr) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%v (line %d, column %d)", e.Err, e.Line, e.Column)
	}
	return e.Err.Error()
}

func locateJSONError(data []byte, off int64) (line, col int) {
	if off <= 0 {
		return 0, 0
	}
	if off > int64(len(data)) {
		off = int64(len(data))
	}
	line, col = 1, 1
	for i := int64(0); i < off-1 && i < int64(len(data)); i++ {
		if data[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return
}

// LoadReservations reads reservations from the specified file path.
func LoadReservations(path string) (Reservations, error) {
	reservations := make(Reservations)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, return empty reservations
			return reservations, nil
		}
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reservations); err != nil {
		return nil, fmt.Errorf("reservations file %s: %w", path, err)
	}
	return reservations, nil
}

// SaveReservations writes reservations to the specified file path.
func SaveReservations(path string, reservations Reservations) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && !os.IsExist(err) {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&reservations); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	_ = f.Sync()
	_ = f.Close()
	return os.Rename(tmp, path)
}

// ParseStrict reads the config file strictly (unknown fields rejected) and
// preserves the same defaults/behavior as the original parseConfigStrict.
// Returns config and reservations loaded from separate file.
// If the config file contains a "reservations" field (old format), it will be
// automatically migrated to the separate reservations file and removed from the config.
func ParseStrict(path string) (Config, Reservations, string, *JSONErr) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, nil, "", &JSONErr{Err: err}
	}

	// Check for old format with reservations in config file
	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err == nil {
		if reservationsRaw, exists := rawMap["reservations"]; exists && reservationsRaw != nil {
			// Migrate reservations from old config format
			var oldReservations Reservations
			reservationsJSON, err := json.Marshal(reservationsRaw)
			if err == nil {
				if err := json.Unmarshal(reservationsJSON, &oldReservations); err == nil && len(oldReservations) > 0 {
					// Determine reservations path
					reservationsPath := ""
					if pathRaw, ok := rawMap["reservations_path"].(string); ok && pathRaw != "" {
						reservationsPath = pathRaw
					}
					if reservationsPath == "" {
						reservationsPath = "/var/dhcplane/dhcplane.reservations"
					} else if !filepath.IsAbs(reservationsPath) {
						cfgDir := filepath.Dir(path)
						reservationsPath = filepath.Join(cfgDir, reservationsPath)
					}

					// Load existing reservations (if any)
					existingReservations, _ := LoadReservations(reservationsPath)

					// Merge old reservations with existing ones (existing take precedence)
					mergedReservations := make(Reservations)
					for k, v := range oldReservations {
						mergedReservations[k] = v
					}
					for k, v := range existingReservations {
						mergedReservations[k] = v // Existing reservations override migrated ones
					}

					// Save merged reservations
					if err := SaveReservations(reservationsPath, mergedReservations); err == nil {
						// Remove reservations from config and save cleaned config
						delete(rawMap, "reservations")
						cleanedJSON, err := json.MarshalIndent(rawMap, "", "  ")
						if err == nil {
							tmp := path + ".tmp"
							if err := os.WriteFile(tmp, cleanedJSON, 0644); err == nil {
								if err := os.Rename(tmp, path); err == nil {
									// Re-read the cleaned config
									data, _ = os.ReadFile(path)
								}
							}
						}
					}
				}
			}
		}
	}

	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		if se, ok := err.(*json.SyntaxError); ok {
			line, col := locateJSONError(data, se.Offset)
			return cfg, nil, "", &JSONErr{Err: err, Line: line, Column: col}
		}
		if ute, ok := err.(*json.UnmarshalTypeError); ok {
			line, col := locateJSONError(data, ute.Offset)
			return cfg, nil, "", &JSONErr{Err: err, Line: line, Column: col}
		}
		return cfg, nil, "", &JSONErr{Err: err}
	}
	// defaults
	if cfg.LeaseSeconds <= 0 {
		cfg.LeaseSeconds = 86400 // 24h
	}
	if cfg.LeaseStickySeconds <= 0 {
		cfg.LeaseStickySeconds = 86400 // default sticky window
	}
	if len(cfg.Pools) == 0 {
		return cfg, nil, "", &JSONErr{Err: errors.New("config: at least one pool required")}
	}

	// Load reservations from separate file
	reservationsPath := cfg.ReservationsPath
	if reservationsPath == "" {
		// Default to /var/dhcplane/
		reservationsPath = "/var/dhcplane/dhcplane.reservations"
	} else if !filepath.IsAbs(reservationsPath) {
		// Relative path: resolve relative to config file directory
		cfgDir := filepath.Dir(path)
		reservationsPath = filepath.Join(cfgDir, reservationsPath)
	}

	reservations, err := LoadReservations(reservationsPath)
	if err != nil {
		return cfg, nil, "", &JSONErr{Err: fmt.Errorf("load reservations: %w", err)}
	}
	cfg.ReservationsPath = reservationsPath // Store resolved path

	return cfg, reservations, reservationsPath, nil
}

/* ----------------- Path resolution helpers ----------------- */

// ResolveFilePath resolves a path that may be a directory or file.
// If the path is a directory (or ends with /), the defaultFilename is appended.
// If the path is a file, it's returned as-is.
// If the path is empty, the defaultFilename is returned.
// If basePath is provided and path is relative, it's resolved relative to basePath.
func ResolveFilePath(path, defaultFilename, basePath string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		if basePath != "" {
			return filepath.Join(basePath, defaultFilename)
		}
		return defaultFilename
	}

	// Check if path ends with a separator (explicit directory)
	if strings.HasSuffix(path, string(filepath.Separator)) || strings.HasSuffix(path, "/") {
		path = filepath.Join(path, defaultFilename)
	} else {
		// Check if it's an existing directory
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			path = filepath.Join(path, defaultFilename)
		}
		// If file doesn't exist, check if the path looks like a directory
		// (no extension and no filename-like pattern)
		// But we'll leave this to the user - if they specify a path without
		// a clear file extension, we'll use it as the filename
	}

	// Make relative paths absolute if basePath is provided
	if basePath != "" && !filepath.IsAbs(path) {
		path = filepath.Join(basePath, path)
	}

	return path
}

/* ----------------- Small helpers (package-local) ----------------- */

// Accepts with ":" "-" or no separators (12 hex chars)
func normalizeMACFlexible(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	// remove separators
	raw := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9':
			return r
		case r >= 'a' && r <= 'f':
			return r
		default:
			return -1
		}
	}, s)
	if len(raw) == 12 {
		var parts []string
		for i := 0; i < 12; i += 2 {
			parts = append(parts, raw[i:i+2])
		}
		s = strings.Join(parts, ":")
	} else {
		// keep original (maybe already colon/dash separated)
		s = strings.ReplaceAll(s, "-", ":")
	}
	m, err := net.ParseMAC(s)
	if err != nil {
		return "", err
	}
	return strings.ToLower(m.String()), nil
}

func parseIPv4(s string) net.IP {
	return net.ParseIP(strings.TrimSpace(s)).To4()
}

func stringInSlice(s string, list []string) bool {
	for _, v := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// ParseHexPayload accepts "01 02", "0x01,0x02", "hex:01:02", etc.
func ParseHexPayload(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "hex:")
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.NewReplacer(" ", "", ":", "", ",", "", "-", "").Replace(s)
	if s == "" {
		return nil, nil
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("hex length must be even")
	}
	return hex.DecodeString(s)
}

// ValidateAndNormalizeConfig applies defaults, normalizes MAC-keyed maps, it returns a COPY of cfg with fixes applied.
func ValidateAndNormalizeConfig(cfg Config) (Config, []string, error) {
	c := cfg
	var warns []string

	// Default: authoritative=true when unset.
	if c.Authoritative == nil {
		v := true
		c.Authoritative = &v
	}

	if len(c.EquipmentTypes) == 0 {
		c.EquipmentTypes = []string{"Switch", "Router", "AP", "Modem", "Gateway"}
	}
	if len(c.ManagementTypes) == 0 {
		c.ManagementTypes = []string{"ssh", "web", "telnet", "serial", "console"}
	}


	if c.DeviceOverrides == nil {
		c.DeviceOverrides = make(map[string]DeviceOverride)
	} else {
		norm := make(map[string]DeviceOverride, len(c.DeviceOverrides))
		for m, ov := range c.DeviceOverrides {
			nm, err := normalizeMACFlexible(m)
			if err != nil {
				return cfg, warns, fmt.Errorf("bad device_overrides MAC %q: %w", m, err)
			}
			norm[nm] = ov
		}
		c.DeviceOverrides = norm
	}

	// VendorClassOverrides: keyed by raw option-60 string
	if c.VendorClassOverrides == nil {
		c.VendorClassOverrides = make(map[string]DeviceOverride)
	}

	// UserClassOverrides77: keyed by user-class string(s)
	if c.UserClassOverrides77 == nil {
		c.UserClassOverrides77 = make(map[string]DeviceOverride)
	}

	if s := strings.TrimSpace(c.VendorSpecific43Hex); s != "" {
		if _, err := ParseHexPayload(s); err != nil {
			return cfg, warns, fmt.Errorf("vendor_specific_43_hex: %w", err)
		}
	}

	if c.BannedMACs == nil {
		c.BannedMACs = make(map[string]DeviceMeta)
	} else {
		for m, meta := range c.BannedMACs {
			nm, err := normalizeMACFlexible(m)
			if err != nil {
				return cfg, warns, fmt.Errorf("bad banned_macs MAC %q: %w", m, err)
			}
			if meta.EquipmentType != "" && !stringInSlice(meta.EquipmentType, c.EquipmentTypes) {
				warns = append(warns, fmt.Sprintf("warning: banned %s has unknown equipment_type %q; allowed: %v",
					nm, meta.EquipmentType, c.EquipmentTypes))
			}
			if meta.ManagementType != "" && !stringInSlice(meta.ManagementType, c.ManagementTypes) {
				warns = append(warns, fmt.Sprintf("warning: banned %s has unknown management_type %q; allowed: %v",
					nm, meta.ManagementType, c.ManagementTypes))
			}
		}
	}

	// Validate Routes33 if enabled
	if c.UseClassfulRoutes33 {
		for i, r := range c.Routes33 {
			gw := parseIPv4(r.Gateway)
			if gw == nil {
				return cfg, warns, fmt.Errorf("routes_33[%d]: bad gateway %q", i, r.Gateway)
			}
			octs := strings.Split(r.Destination, ".")
			if len(octs) != 4 {
				return cfg, warns, fmt.Errorf("routes_33[%d]: bad destination %q", i, r.Destination)
			}
			classful := (octs[1] == "0" && octs[2] == "0" && octs[3] == "0") ||
				(octs[2] == "0" && octs[3] == "0") ||
				(octs[3] == "0")
			if !classful || parseIPv4(r.Destination) == nil {
				return cfg, warns, fmt.Errorf("routes_33[%d]: destination %q must be classful network (a.0.0.0 | a.b.0.0 | a.b.c.0)", i, r.Destination)
			}
		}
	}

	if c.NetBIOSNodeType46 != 0 {
		switch c.NetBIOSNodeType46 {
		case 1, 2, 4, 8:
		default:
			return cfg, warns, fmt.Errorf("netbios_node_type_46 must be one of {1,2,4,8}")
		}
	}

	if c.MaxDHCPMessageSize57 != 0 && c.MaxDHCPMessageSize57 < 576 {
		return cfg, warns, fmt.Errorf("max_dhcp_message_size_57 must be >= 576")
	}

	for i, s := range c.TFTPServers150 {
		if parseIPv4(s) == nil {
			return cfg, warns, fmt.Errorf("tftp_servers_150[%d]: bad IPv4 %q", i, s)
		}
	}

	// Default paths for data files
	const (
		defaultDataDir = "/var/dhcplane"
		defaultLogDir  = "/var/log/dhcplane"
	)

	// File paths defaults and validation
	// LeaseDBPath: resolve directory to file if needed, default to /var/dhcplane/
	if c.LeaseDBPath == "" {
		c.LeaseDBPath = ResolveFilePath(defaultDataDir, "dhcplane.leases", "")
	} else {
		c.LeaseDBPath = ResolveFilePath(c.LeaseDBPath, "dhcplane.leases", "")
	}

	// PIDFile: resolve directory to file if needed, default to /var/dhcplane/
	if c.PIDFile == "" {
		c.PIDFile = ResolveFilePath(defaultDataDir, "dhcplane.pid", "")
	} else {
		c.PIDFile = ResolveFilePath(c.PIDFile, "dhcplane.pid", "")
	}

	// ReservationsPath: resolve directory to file if needed, default to /var/dhcplane/
	if c.ReservationsPath == "" {
		c.ReservationsPath = ResolveFilePath(defaultDataDir, "dhcplane.reservations", "")
	} else {
		c.ReservationsPath = ResolveFilePath(c.ReservationsPath, "dhcplane.reservations", "")
	}

	// Logging: support both new log_file field and legacy path/filename
	c.Logging.LogFile = strings.TrimSpace(c.Logging.LogFile)
	c.Logging.Path = strings.TrimSpace(c.Logging.Path)
	c.Logging.Filename = strings.TrimSpace(c.Logging.Filename)

	if c.Logging.LogFile != "" {
		// New style: single log_file path (may be dir or file)
		c.Logging.LogFile = ResolveFilePath(c.Logging.LogFile, "dhcplane.log", "")
		// Clear legacy fields to avoid confusion
		c.Logging.Path = ""
		c.Logging.Filename = ""
	} else if c.Logging.Path != "" || c.Logging.Filename != "" {
		// Legacy style: separate path and filename
		if c.Logging.Filename == "" {
			c.Logging.Filename = "dhcplane.log"
		}
	} else {
		// No logging config at all - use default /var/log/dhcplane/
		c.Logging.LogFile = ResolveFilePath(defaultLogDir, "dhcplane.log", "")
	}

	if c.Logging.MaxSize <= 0 {
		c.Logging.MaxSize = 20
	}
	if c.Logging.MaxBackups < 0 {
		return cfg, warns, fmt.Errorf("logging.max_backups must be >= 0")
	}
	if c.Logging.MaxBackups == 0 {
		c.Logging.MaxBackups = 5
	}
	if c.Logging.MaxAge < 0 {
		return cfg, warns, fmt.Errorf("logging.max_age must be >= 0")
	}
	if !c.Logging.Compress {
		c.Logging.Compress = true
	}

	// DetectDHCPServers: defaults, clamps, normalization, validation
	{
		d := c.DetectDHCPServers

		// Defaults
		if !d.Enabled {
			if d.ActiveProbe == "" && d.ProbeInterval == 0 && d.RateLimit == 0 && len(d.WhitelistServers) == 0 {
				d.Enabled = true
			}
		}
		if d.ActiveProbe == "" {
			d.ActiveProbe = "off"
		}
		d.ActiveProbe = strings.ToLower(strings.TrimSpace(d.ActiveProbe))
		switch d.ActiveProbe {
		case "off", "safe", "aggressive":
		default:
			warns = append(warns, fmt.Sprintf("warning: detect_dhcp_servers.active_probe %q not in {off,safe,aggressive}; using off", d.ActiveProbe))
			d.ActiveProbe = "off"
		}

		if d.ProbeInterval <= 0 {
			d.ProbeInterval = 600
		}
		if d.ProbeInterval < 60 {
			warns = append(warns, "warning: detect_dhcp_servers.probe_interval clamped to 60s minimum")
			d.ProbeInterval = 60
		}

		if d.FirstScan <= 0 {
			d.FirstScan = 60
		}
		if d.FirstScan < 10 {
			warns = append(warns, "warning: detect_dhcp_servers.first_scan clamped to 10s minimum")
			d.FirstScan = 10
		}

		if d.RateLimit <= 0 {
			d.RateLimit = 6
		}
		if d.RateLimit < 1 {
			d.RateLimit = 1
		}

		// Normalize whitelist entries
		if len(d.WhitelistServers) > 0 {
			out := make([]string, 0, len(d.WhitelistServers))
			for _, w := range d.WhitelistServers {
				w = strings.TrimSpace(w)
				if w == "" {
					continue
				}
				if ip := parseIPv4(w); ip != nil {
					out = append(out, ip.String())
					continue
				}
				if nm, err := normalizeMACFlexible(w); err == nil {
					out = append(out, nm)
					continue
				}
				warns = append(warns, fmt.Sprintf("warning: detect_dhcp_servers.whitelist_servers entry %q ignored (not IPv4 or MAC)", w))
			}
			d.WhitelistServers = out
		}

		c.DetectDHCPServers = d
	}

	// REST API validation (dnsplane-aligned keys)
	c.APIPort = strings.TrimSpace(c.APIPort)
	c.APIBind = strings.TrimSpace(c.APIBind)
	c.APIAuthToken = strings.TrimSpace(c.APIAuthToken)
	c.APITLSCertFile = strings.TrimSpace(c.APITLSCertFile)
	c.APITLSKeyFile = strings.TrimSpace(c.APITLSKeyFile)
	if c.API {
		if c.APIPort == "" {
			return cfg, warns, fmt.Errorf("api: true requires non-empty apiport")
		}
		if c.APIBind != "" {
			if ip := net.ParseIP(c.APIBind); ip == nil {
				return cfg, warns, fmt.Errorf("api_bind: invalid IP %q", c.APIBind)
			}
		}
		certSet := c.APITLSCertFile != ""
		keySet := c.APITLSKeyFile != ""
		if certSet != keySet {
			return cfg, warns, fmt.Errorf("api_tls_cert and api_tls_key must both be set or both empty")
		}
		if c.APIRateLimitPerIP > 0 && c.APIRateLimitBurst <= 0 {
			c.APIRateLimitBurst = 20
		}
		if clash := apiConsolePortClash(c.ConsoleTCPAddress, c.APIPort); clash != "" {
			return cfg, warns, fmt.Errorf("api: %s", clash)
		}
	}

	return c, warns, nil
}

// apiConsolePortClash reports an error message if console TCP uses the same port as the REST API.
func apiConsolePortClash(consoleTCP, apiPort string) string {
	consoleTCP = strings.TrimSpace(consoleTCP)
	if consoleTCP == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(consoleTCP)
	if err != nil {
		return ""
	}
	if port == strings.TrimSpace(apiPort) {
		return fmt.Sprintf("apiport %s conflicts with console_tcp_address %q (same TCP port)", apiPort, consoleTCP)
	}
	return ""
}
