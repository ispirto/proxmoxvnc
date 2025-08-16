package vnc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"newproxmoxvnc/internal/logger"
	"newproxmoxvnc/pkg/api"
)

// Server provides an HTTP server for VNC connections
type Server struct {
	httpServer   *http.Server
	proxy        *WebSocketProxy
	port         int
	mu           sync.Mutex
	running      bool
	logger       *logger.Logger
	publicIP     string            // Public IP for URL generation
	vncParams    map[string]string // VNC parameters for secure access
	novncPath    string            // Path to noVNC files on disk
}


// NewServer creates a new HTTP server with a shared logger
func NewServer(sharedLogger *logger.Logger) *Server {
	return NewServerWithIP(sharedLogger, "")
}

// NewServerWithIP creates a new HTTP server with logger and public IP
func NewServerWithIP(sharedLogger *logger.Logger, publicIP string) *Server {
	var serverLogger *logger.Logger
	
	if sharedLogger != nil {
		serverLogger = sharedLogger
	} else {
		// Create a logger using global settings
		serverLogger = logger.CreateComponentLogger("VNC-SERVER")
	}
	
	serverLogger.Debug("Creating new VNC server instance")
	
	// Default noVNC path - can be overridden
	novncPath := "./internal/vnc/novnc"
	
	// Check if noVNC files exist at the default path
	if _, err := os.Stat(novncPath); os.IsNotExist(err) {
		// Try alternative path
		novncPath = "/usr/share/novnc"
		if _, err := os.Stat(novncPath); os.IsNotExist(err) {
			serverLogger.Error("noVNC files not found at default paths")
		}
	}
	
	server := &Server{
		logger:    serverLogger,
		vncParams: make(map[string]string),
		publicIP:  publicIP,
		novncPath: novncPath,
	}
	
	if publicIP != "" {
		serverLogger.Info("Using configured public IP: %s", server.publicIP)
	} else {
		serverLogger.Info("No public IP configured, using localhost")
		server.publicIP = "localhost"
	}
	
	serverLogger.Info("Using noVNC files from: %s", novncPath)
	
	return server
}

// SetNoVNCPath allows setting a custom path for noVNC files
func (s *Server) SetNoVNCPath(path string) error {
	// Verify the path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("noVNC path does not exist: %s", path)
	}
	
	// Check for vnc.html to ensure it's a valid noVNC directory
	vncHtmlPath := filepath.Join(path, "vnc.html")
	if _, err := os.Stat(vncHtmlPath); os.IsNotExist(err) {
		return fmt.Errorf("vnc.html not found in noVNC path: %s", path)
	}
	
	s.novncPath = path
	s.logger.Info("noVNC path set to: %s", path)
	return nil
}

// StartVMVNCServer starts the server for a VM VNC connection
func (s *Server) StartVMVNCServer(client *api.Client, vm *api.VM) (string, error) {
	return s.StartVMVNCServerWithSession(client, vm, nil)
}

// StartVMVNCServerWithSession starts the server with session notifications
func (s *Server) StartVMVNCServerWithSession(client *api.Client, vm *api.VM, session SessionNotifier) (string, error) {
	s.logger.Info("Starting VM VNC server for: %s (ID: %d, Type: %s, Node: %s)", 
		vm.Name, vm.ID, vm.Type, vm.Node)
	
	// Create proxy configuration
	s.logger.Debug("Creating VNC proxy configuration for VM %s", vm.Name)
	
	proxyConfigLogger := logger.CreateComponentLogger("PROXY-CFG")
	config, err := CreateVMProxyConfig(client, vm, proxyConfigLogger)
	if err != nil {
		s.logger.Error("Failed to create VM proxy config for %s: %v", vm.Name, err)
		return "", fmt.Errorf("failed to create VM proxy config: %w", err)
	}
	
	s.logger.Debug("VM proxy config created - Port: %s, VM Type: %s", config.Port, config.VMType)
	
	// Create WebSocket proxy with session notifications
	s.logger.Debug("Creating WebSocket proxy for VM %s", vm.Name)
	wsProxyLogger := logger.CreateComponentLogger("WS-PROXY")
	s.proxy = NewWebSocketProxy(config, session, wsProxyLogger)
	
	// Start HTTP server
	s.logger.Debug("Starting HTTP server for VM %s", vm.Name)
	
	if err := s.startHTTPServer(); err != nil {
		s.logger.Error("Failed to start HTTP server for VM %s: %v", vm.Name, err)
		return "", fmt.Errorf("failed to start HTTP server: %w", err)
	}
	
	// Store VNC parameters securely in memory
	s.mu.Lock()
	s.vncParams["autoconnect"] = "true"
	s.vncParams["reconnect"] = "true"
	s.vncParams["password"] = config.Password
	s.vncParams["path"] = "vnc-proxy"
	s.vncParams["resize"] = "scale"
	s.mu.Unlock()
	
	// Generate simple noVNC URL without exposing parameters
	vncURL := fmt.Sprintf("http://%s:%d/", s.publicIP, s.port)
	
	s.logger.Info("VM VNC server started successfully for %s on port %d", vm.Name, s.port)
	s.logger.Debug("VM VNC URL generated: %s (parameters stored securely)", vncURL)
	
	return vncURL, nil
}

// startHTTPServer starts the HTTP server on an available port
func (s *Server) startHTTPServer() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.running {
		s.logger.Debug("HTTP server already running on port %d", s.port)
		return nil
	}
	
	s.logger.Debug("Finding available port for HTTP server")
	
	// Find an available port on all interfaces
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		s.logger.Error("Failed to find available port: %v", err)
		return fmt.Errorf("failed to find available port: %w", err)
	}
	
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("failed to get TCP address from listener")
	}
	
	s.port = tcpAddr.Port
	if err := listener.Close(); err != nil {
		s.logger.Error("Failed to close listener: %v", err)
	}
	
	s.logger.Info("Allocated port %d for HTTP server", s.port)
	
	// Create HTTP server
	mux := http.NewServeMux()
	
	// Serve noVNC client files from disk
	s.logger.Debug("Setting up noVNC file server from: %s", s.novncPath)
	
	// Verify noVNC path exists
	if _, err := os.Stat(s.novncPath); os.IsNotExist(err) {
		s.logger.Error("noVNC path does not exist: %s", s.novncPath)
		return fmt.Errorf("noVNC path does not exist: %s", s.novncPath)
	}
	
	// Serve dynamic mandatory.json with VNC parameters
	mux.HandleFunc("/mandatory.json", s.handleMandatoryJSON)
	
	// Custom handler to serve vnc.html at root and static files
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Determine the file path
		filePath := r.URL.Path
		if filePath == "/" {
			filePath = "/vnc.html"
		}
		
		// Construct full file path
		fullPath := filepath.Join(s.novncPath, filePath)
		
		// Security: Clean the path to prevent directory traversal
		fullPath = filepath.Clean(fullPath)
		
		// Ensure the path is still within novncPath
		if !filepath.HasPrefix(fullPath, filepath.Clean(s.novncPath)) {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		
		// Check if file exists
		info, err := os.Stat(fullPath)
		if err != nil {
			if os.IsNotExist(err) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		
		// Don't serve directories
		if info.IsDir() {
			http.NotFound(w, r)
			return
		}
		
		// Serve the file
		http.ServeFile(w, r, fullPath)
	})
	
	// WebSocket proxy endpoint
	s.logger.Debug("Setting up WebSocket proxy endpoint")
	mux.HandleFunc("/vnc-proxy", s.proxy.HandleWebSocketProxy)
	
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      mux,
		ReadTimeout:  0,                // No timeout for WebSocket connections
		WriteTimeout: 0,                // No timeout for WebSocket connections
		IdleTimeout:  10 * time.Minute, // 10 minutes idle timeout
	}
	
	s.logger.Debug("Starting HTTP server on %s", s.httpServer.Addr)
	
	// Start server in background
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server error: %v", err)
		} else if err == http.ErrServerClosed {
			s.logger.Debug("HTTP server closed normally")
		}
	}()
	
	s.running = true
	s.logger.Info("HTTP server started successfully on port %d", s.port)
	
	return nil
}

// Stop stops the HTTP server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if !s.running || s.httpServer == nil {
		s.logger.Debug("HTTP server not running, no action needed")
		return nil
	}
	
	s.logger.Info("Stopping HTTP server on port %d", s.port)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err := s.httpServer.Shutdown(ctx)
	if err != nil {
		s.logger.Error("Failed to shutdown HTTP server gracefully: %v", err)
	} else {
		s.logger.Debug("HTTP server shutdown gracefully")
	}
	
	s.running = false
	s.httpServer = nil
	s.proxy = nil
	s.vncParams = make(map[string]string)
	
	s.logger.Info("HTTP server stopped successfully")
	
	return err
}

// GetPort returns the port the server is running on
func (s *Server) GetPort() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.port
}

// IsRunning returns whether the server is currently running
func (s *Server) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// handleMandatoryJSON serves dynamic mandatory.json with VNC parameters
func (s *Server) handleMandatoryJSON(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	s.mu.Lock()
	params := make(map[string]string)
	for k, v := range s.vncParams {
		params[k] = v
	}
	s.mu.Unlock()
	
	// Return parameters as JSON
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	
	jsonData, err := json.Marshal(params)
	if err != nil {
		s.logger.Error("Failed to marshal mandatory params to JSON: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	w.Write(jsonData)
}