// Package interfaces defines the core interfaces used throughout ProxmoxVNC
package interfaces

// Config defines the interface for accessing application configuration
type Config interface {
	// GetAddr returns the Proxmox server URL
	GetAddr() string
	
	// GetUser returns the username (without realm)
	GetUser() string
	
	// GetPassword returns the password
	GetPassword() string
	
	// GetRealm returns the authentication realm
	GetRealm() string
	
	// GetInsecure returns true if TLS verification should be skipped
	GetInsecure() bool
}