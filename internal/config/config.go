// Package config provides configuration management for ProxmoxVNC
package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
)

// Config represents the application configuration loaded from JSON
type Config struct {
	// Authorization token for API access
	Authorization string `json:"authorization"`
	
	// Logging configuration
	LoggingEnabled bool   `json:"logging_enabled"`
	LoggingLevel   string `json:"logging_level"`
	LogFile        string `json:"log_file,omitempty"`
	
	// Public IP configuration for VNC URLs
	PublicIP string `json:"public_ip"`
	
	// Router binding configuration
	RouterIP   string `json:"router_ip,omitempty"`   // IP to bind the router to (default: 0.0.0.0)
	RouterPort int    `json:"router_port"`           // Port to bind the router to (default: 9999)
	
	// NoVNC path for static file serving (optional)
	NoVNCPath string `json:"novnc_path,omitempty"`
}

// ProxmoxConfig represents the Proxmox connection parameters passed via API
type ProxmoxConfig struct {
	// Hostname is the IP address or hostname of the Proxmox server
	Hostname string `json:"hostname"`
	
	// Port is the Proxmox server port (default: 8006)
	Port string `json:"port"`
	
	// Node is the Proxmox node name to connect to
	Node string `json:"node"`
	
	// Username with realm for Proxmox authentication
	Username string `json:"username"`
	
	// Password for authentication
	Password string `json:"password"`
	
	// VM ID to connect to
	VMID string `json:"vmid"`
	
	// Derived fields (not from JSON)
	addr     string // Full Proxmox server URL
	user     string // Username part before @
	realm    string // Realm part after @
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(filepath string) (*Config, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate required fields
	if config.Authorization == "" {
		return nil, fmt.Errorf("authorization is required in config")
	}
	if config.PublicIP == "" {
		return nil, fmt.Errorf("public_ip is required in config")
	}
	
	// Set default router port if not specified
	if config.RouterPort == 0 {
		config.RouterPort = 9999
	}

	return &config, nil
}

// GetAuthorization returns the authorization token
func (c *Config) GetAuthorization() string {
	return c.Authorization
}

// GetPublicIP returns the configured public IP
func (c *Config) GetPublicIP() string {
	return c.PublicIP
}

// GetRouterPort returns the configured router port (default: 9999)
func (c *Config) GetRouterPort() int {
	if c.RouterPort == 0 {
		return 9999 // Default port
	}
	return c.RouterPort
}

// GetRouterIP returns the IP address to bind the router to (default: 0.0.0.0)
func (c *Config) GetRouterIP() string {
	if c.RouterIP == "" {
		return "0.0.0.0" // Default to all interfaces
	}
	return c.RouterIP
}

// ProxmoxConfig methods

// PrepareProxmoxConfig processes the Proxmox configuration by:
// - Setting default port 8006 if not specified
// - Parsing username@realm format
// - Building the full HTTPS URL
func PrepareProxmoxConfig(cfg *ProxmoxConfig) error {
	// Parse port
	if cfg.Port == "" {
		cfg.Port = "8006"
	}
	
	// Parse username and realm
	parts := strings.Split(cfg.Username, "@")
	if len(parts) == 2 {
		cfg.user = parts[0]
		cfg.realm = parts[1]
	} else {
		cfg.user = cfg.Username
		cfg.realm = "pve" // Default realm
	}
	
	// Build the full Proxmox URL
	cfg.addr = fmt.Sprintf("https://%s:%s", cfg.Hostname, cfg.Port)
	
	return nil
}

// GetAddr returns the full server address
func (c *ProxmoxConfig) GetAddr() string {
	return c.addr
}

// GetUser returns the username part (before @)
func (c *ProxmoxConfig) GetUser() string {
	return c.user
}

// GetPassword returns the password
func (c *ProxmoxConfig) GetPassword() string {
	return c.Password
}

// GetRealm returns the realm part (after @)
func (c *ProxmoxConfig) GetRealm() string {
	return c.realm
}

// GetInsecure returns true to skip TLS verification (for self-signed certs)
func (c *ProxmoxConfig) GetInsecure() bool {
	return true
}

// GetNodeName returns the node name
func (c *ProxmoxConfig) GetNodeName() string {
	return c.Node
}

