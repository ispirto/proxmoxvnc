// Package vnc provides VNC connection services for Proxmox VMs
package vnc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"

	"newproxmoxvnc/internal/logger"
	"newproxmoxvnc/pkg/api"
)

// ProxyConfig holds configuration for the VNC WebSocket proxy
type ProxyConfig struct {
	// VNC proxy details from Proxmox API
	Port     string
	Ticket   string
	Password string
	
	// Proxmox server details
	ProxmoxHost string
	NodeName    string
	VMID        int
	VMType      string // "qemu" or "lxc"
	
	// Authentication
	AuthToken string
	
	// Connection settings
	Timeout time.Duration
}

// WebSocketProxy handles the bidirectional WebSocket proxy
type WebSocketProxy struct {
	config   *ProxyConfig
	upgrader websocket.Upgrader
	logger   *logger.Logger
	session  SessionNotifier
}

// SessionNotifier interface for session lifecycle notifications
type SessionNotifier interface {
	OnClientConnected()
	OnClientDisconnected()
	UpdateLastUsed()
}


// NewWebSocketProxy creates a new WebSocket proxy with session notifications and logger
func NewWebSocketProxy(config *ProxyConfig, session SessionNotifier, sharedLogger *logger.Logger) *WebSocketProxy {
	var proxyLogger *logger.Logger
	
	if sharedLogger != nil {
		proxyLogger = sharedLogger
	} else {
		// Create a logger using global settings
		proxyLogger = logger.CreateComponentLogger("WS-PROXY")
	}
	
	targetName := getTargetName(config)
	proxyLogger.Info("Creating new WebSocket proxy for %s (Type: %s, Node: %s)",
		targetName, config.VMType, config.NodeName)
	
	return &WebSocketProxy{
		config:  config,
		logger:  proxyLogger,
		session: session,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// Allow connections from any origin
				// Security is handled by authentication layer
				return true
			},
		},
	}
}

// getTargetName returns a descriptive name for the target
func getTargetName(config *ProxyConfig) string {
	if config.VMType == "node" {
		return config.NodeName
	}
	return fmt.Sprintf("VM-%d", config.VMID)
}

// HandleWebSocketProxy handles incoming WebSocket connections from noVNC client
func (p *WebSocketProxy) HandleWebSocketProxy(w http.ResponseWriter, r *http.Request) {
	targetName := getTargetName(p.config)
	p.logger.Info("Handling WebSocket proxy request for %s from %s", targetName, r.RemoteAddr)
	
	// Upgrade HTTP connection to WebSocket
	clientConn, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		p.logger.Error("Failed to upgrade connection for %s: %v", targetName, err)
		http.Error(w, fmt.Sprintf("Failed to upgrade connection: %v", err), http.StatusBadRequest)
		return
	}
	
	defer func() {
		p.logger.Debug("Closing client WebSocket connection for %s", targetName)
		clientConn.Close()
	}()
	
	p.logger.Info("WebSocket connection established with client for %s", targetName)
	
	// Notify session about client connection
	if p.session != nil {
		p.session.OnClientConnected()
		p.logger.Debug("Notified session about client connection for %s", targetName)
	}
	
	// Ensure we notify session about disconnection
	defer func() {
		if p.session != nil {
			p.session.OnClientDisconnected()
			p.logger.Debug("Notified session about client disconnection for %s", targetName)
		}
	}()
	
	// Connect to Proxmox VNC websocket
	proxmoxConn, err := p.connectToProxmox()
	if err != nil {
		p.logger.Error("Failed to connect to Proxmox for %s: %v", targetName, err)
		clientConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr,
				fmt.Sprintf("Failed to connect to Proxmox: %v", err)))
		return
	}
	
	defer func() {
		p.logger.Debug("Closing Proxmox WebSocket connection for %s", targetName)
		proxmoxConn.Close()
	}()
	
	p.logger.Info("WebSocket connection established with Proxmox for %s", targetName)
	
	// Start bidirectional proxy
	ctx, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
	defer cancel()
	
	p.logger.Info("Starting bidirectional WebSocket proxy for %s (timeout: %v)", 
		targetName, p.config.Timeout)
	
	// Channel to signal when either connection closes
	done := make(chan error, 2)
	
	// Start ping ticker to keep connections alive
	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()
	
	go func() {
		for {
			select {
			case <-pingTicker.C:
				// Send ping to both connections
				if err := clientConn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
					p.logger.Debug("Failed to ping client for %s: %v", targetName, err)
					return
				}
				if err := proxmoxConn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
					p.logger.Debug("Failed to ping Proxmox for %s: %v", targetName, err)
					return
				}
				
				p.logger.Debug("Sent keepalive pings for %s", targetName)
				
				if p.session != nil {
					p.session.UpdateLastUsed()
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	
	// Proxy messages from client to Proxmox
	go func() {
		p.logger.Debug("Starting client->Proxmox relay for %s", targetName)
		done <- p.proxyMessages(clientConn, proxmoxConn, "client->proxmox", targetName)
	}()
	
	// Proxy messages from Proxmox to client
	go func() {
		p.logger.Debug("Starting Proxmox->client relay for %s", targetName)
		done <- p.proxyMessages(proxmoxConn, clientConn, "proxmox->client", targetName)
	}()
	
	// Wait for either connection to close or timeout
	select {
	case err := <-done:
		if err != nil {
			p.logger.Error("WebSocket proxy error for %s: %v", targetName, err)
		} else {
			p.logger.Info("WebSocket proxy connection closed normally for %s", targetName)
		}
	case <-ctx.Done():
		p.logger.Info("WebSocket proxy timeout reached for %s", targetName)
	}
	
	p.logger.Info("WebSocket proxy session ended for %s", targetName)
}

// connectToProxmox establishes a WebSocket connection to the Proxmox VNC endpoint
func (p *WebSocketProxy) connectToProxmox() (*websocket.Conn, error) {
	targetName := getTargetName(p.config)
	
	// Build the Proxmox VNC websocket URL
	var vncPath string
	if p.config.VMType == api.VMTypeQemu {
		vncPath = fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/vncwebsocket",
			p.config.NodeName, p.config.VMID)
	} else if p.config.VMType == api.VMTypeLXC {
		vncPath = fmt.Sprintf("/api2/json/nodes/%s/lxc/%d/vncwebsocket",
			p.config.NodeName, p.config.VMID)
	} else {
		return nil, fmt.Errorf("unsupported VM type: %s", p.config.VMType)
	}
	
	// Add query parameters
	vncURL := fmt.Sprintf("wss://%s%s?port=%s&vncticket=%s",
		p.config.ProxmoxHost, vncPath, p.config.Port, url.QueryEscape(p.config.Ticket))
	
	p.logger.Debug("Proxmox VNC websocket URL for %s: %s", targetName, vncURL)
	
	// Create WebSocket dialer with TLS config
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skip TLS verification for self-signed certs
		},
		HandshakeTimeout: 10 * time.Second,
	}
	
	// Set up headers for authentication
	headers := make(http.Header)
	
	if p.config.AuthToken != "" {
		// Always using cookie authentication (password-based auth returns PVEAuthCookie format)
		headers.Set("Cookie", p.config.AuthToken)
		p.logger.Debug("Using cookie authentication for %s", targetName)
	}
	
	// Connect to Proxmox VNC websocket
	p.logger.Info("Connecting to Proxmox VNC websocket for %s", targetName)
	
	conn, resp, err := dialer.Dial(vncURL, headers)
	if err != nil {
		if resp != nil {
			p.logger.Error("Failed to connect to Proxmox VNC websocket for %s (HTTP %d): %v",
				targetName, resp.StatusCode, err)
			resp.Body.Close()
			return nil, fmt.Errorf("failed to connect to Proxmox VNC websocket (status %d): %w",
				resp.StatusCode, err)
		}
		
		p.logger.Error("Failed to connect to Proxmox VNC websocket for %s: %v", targetName, err)
		return nil, fmt.Errorf("failed to connect to Proxmox VNC websocket: %w", err)
	}
	
	if resp != nil {
		resp.Body.Close()
	}
	
	p.logger.Info("Successfully connected to Proxmox VNC websocket for %s", targetName)
	return conn, nil
}

// proxyMessages handles message forwarding between WebSocket connections
func (p *WebSocketProxy) proxyMessages(src, dst *websocket.Conn, direction, targetName string) error {
	var messageCount int
	
	// Set initial read deadline
	if err := src.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
		p.logger.Debug("Failed to set read deadline (%s) for %s: %v", direction, targetName, err)
	}
	
	src.SetPongHandler(func(string) error {
		p.logger.Debug("Pong received (%s) for %s", direction, targetName)
		if err := src.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			p.logger.Debug("Failed to reset read deadline (%s) for %s: %v", direction, targetName, err)
		}
		return nil
	})
	
	for {
		messageType, message, err := src.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				p.logger.Error("Unexpected close error (%s) for %s: %v", direction, targetName, err)
				return fmt.Errorf("unexpected close error (%s): %w", direction, err)
			}
			
			p.logger.Debug("Normal close for %s (%s) after %d messages", direction, targetName, messageCount)
			return nil // Normal close
		}
		
		// Reset read deadline on each message
		if err := src.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			p.logger.Debug("Failed to reset read deadline (%s) for %s: %v", direction, targetName, err)
		}
		
		messageCount++
		if messageCount == 1 {
			p.logger.Debug("First message received (%s) for %s: type=%d, size=%d bytes",
				direction, targetName, messageType, len(message))
		} else if messageCount%100 == 0 {
			p.logger.Debug("Message count (%s) for %s: %d messages processed",
				direction, targetName, messageCount)
		}
		
		err = dst.WriteMessage(messageType, message)
		if err != nil {
			p.logger.Error("Write error (%s) for %s after %d messages: %v",
				direction, targetName, messageCount, err)
			return fmt.Errorf("write error (%s): %w", direction, err)
		}
		
		if p.session != nil {
			p.session.UpdateLastUsed()
		}
	}
}


// CreateVMProxyConfig creates a proxy configuration for a VM VNC connection
func CreateVMProxyConfig(client *api.Client, vm *api.VM, sharedLogger *logger.Logger) (*ProxyConfig, error) {
	var configLogger *logger.Logger
	
	if sharedLogger != nil {
		configLogger = sharedLogger
	} else {
		// Create a logger using global settings
		configLogger = logger.CreateComponentLogger("PROXY-CFG")
	}
	
	configLogger.Info("Creating VNC proxy configuration for VM: %s (ID: %d, Type: %s, Node: %s)",
		vm.Name, vm.ID, vm.Type, vm.Node)
	
	// Get VNC proxy details from Proxmox API
	proxy, err := client.GetVNCProxyWithWebSocket(vm)
	if err != nil {
		configLogger.Error("Failed to get VNC proxy from API for VM %s: %v", vm.Name, err)
		return nil, fmt.Errorf("failed to create VNC proxy: %w", err)
	}
	
	// Extract hostname from client base URL
	baseURL := client.GetBaseURL()
	u, err := url.Parse(baseURL)
	if err != nil {
		configLogger.Error("Failed to parse client base URL for VM %s: %v", vm.Name, err)
		return nil, fmt.Errorf("failed to parse base URL: %w", err)
	}
	
	configLogger.Debug("Extracted Proxmox host for VM %s: %s", vm.Name, u.Host)
	
	// Get authentication token
	authToken := client.GetAuthToken()
	
	// For LXC containers, use the ticket as password if no password is generated
	password := proxy.Password
	if password == "" && vm.Type == api.VMTypeLXC {
		password = proxy.Ticket
		configLogger.Debug("Using ticket as password for LXC container %s", vm.Name)
	}
	
	config := &ProxyConfig{
		Port:        proxy.Port,
		Ticket:      proxy.Ticket,
		Password:    password,
		ProxmoxHost: u.Host,
		NodeName:    vm.Node,
		VMID:        vm.ID,
		VMType:      vm.Type,
		AuthToken:   authToken,
		Timeout:     30 * time.Minute,
	}
	
	configLogger.Info("VNC proxy configuration created successfully for VM %s", vm.Name)
	return config, nil
}