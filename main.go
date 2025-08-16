package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ispirto/proxmoxvnc/internal/config"
	"github.com/ispirto/proxmoxvnc/internal/logger"
	"github.com/ispirto/proxmoxvnc/internal/proxyprocess"
)

// TokenSession represents a pending VNC session created via /create endpoint
// It stores the Proxmox credentials temporarily until consumed by /vnc/<token>
type TokenSession struct {
	Token         string
	ProxmoxConfig *config.ProxmoxConfig
	CreatedAt     time.Time
}

// SessionStatus represents the lifecycle state of a VNC session
type SessionStatus string

const (
	SessionStatusCreated      SessionStatus = "created"
	SessionStatusActive       SessionStatus = "active"
	SessionStatusDisconnected SessionStatus = "disconnected"
)

// RecentSession tracks active and recent VNC sessions for monitoring
type RecentSession struct {
	SessionID    string
	URL          string
	NodeName     string
	VMID         string
	CreatedAt    time.Time
	ConnectedAt  *time.Time // nil until first connection
	EndedAt      *time.Time // nil until disconnection
	Port         int
	Status       SessionStatus
}

// VNCRouter handles HTTP routing and session management for the VNC proxy service
type VNCRouter struct {
	config         *config.Config
	configPath     string
	tokenSessions  map[string]*TokenSession   // One-time tokens waiting to be consumed
	recentSessions map[string]*RecentSession  // Active and recent sessions for monitoring
	mu             sync.RWMutex               // Protects both maps
}

// NewVNCRouter creates a new VNC router with the given configuration
func NewVNCRouter(cfg *config.Config, configPath string) *VNCRouter {
	return &VNCRouter{
		config:         cfg,
		configPath:     configPath,
		tokenSessions:  make(map[string]*TokenSession),
		recentSessions: make(map[string]*RecentSession),
	}
}

// generateToken creates a cryptographically secure random token
func generateToken() string {
	bytes := make([]byte, 10)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// OnSessionConnected is called when a client connects to a VNC session
func (r *VNCRouter) OnSessionConnected(sessionKey string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if session, exists := r.recentSessions[sessionKey]; exists {
		now := time.Now()
		session.ConnectedAt = &now
		session.Status = SessionStatusActive
		logger.Info("Session %s marked as active (client connected)", session.SessionID)
	}
}

// OnSessionDisconnected is called when a client disconnects from a VNC session
func (r *VNCRouter) OnSessionDisconnected(sessionKey string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if session, exists := r.recentSessions[sessionKey]; exists {
		now := time.Now()
		session.EndedAt = &now
		session.Status = SessionStatusDisconnected
		logger.Info("Session %s marked as disconnected", session.SessionID)
	}
}

// handleCreate processes POST /create requests to generate one-time VNC session tokens
// Expects multipart form with 'params' field containing ProxmoxConfig JSON
func (r *VNCRouter) handleCreate(w http.ResponseWriter, req *http.Request) {
	logger.Debug("Create request from %s", req.RemoteAddr)
	
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// Check authorization header
	authHeader := req.Header.Get("Authorization")
	if authHeader != r.config.GetAuthorization() {
		logger.Error("Invalid authorization from %s", req.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Parse multipart form
	err := req.ParseMultipartForm(10 << 20) // 10MB max
	if err != nil {
		logger.Error("Failed to parse form: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"token":  "",
		})
		return
	}
	
	// Get params from form
	paramsStr := req.FormValue("params")
	if paramsStr == "" {
		logger.Error("Missing params in request")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"token":  "",
		})
		return
	}
	
	// Parse JSON params
	var proxmoxConfig config.ProxmoxConfig
	err = json.Unmarshal([]byte(paramsStr), &proxmoxConfig)
	if err != nil {
		logger.Error("Failed to parse params JSON: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"token":  "",
		})
		return
	}
	
	// Prepare the Proxmox configuration
	err = config.PrepareProxmoxConfig(&proxmoxConfig)
	if err != nil {
		logger.Error("Failed to prepare proxmox config: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"token":  "",
		})
		return
	}
	
	// Generate token and store session
	token := generateToken()
	
	r.mu.Lock()
	r.tokenSessions[token] = &TokenSession{
		Token:         token,
		ProxmoxConfig: &proxmoxConfig,
		CreatedAt:     time.Now(),
	}
	r.mu.Unlock()
	
	logger.Info("Created token %s for VM %s on node %s", token, proxmoxConfig.VMID, proxmoxConfig.Node)
	
	// Return success response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"token":  token,
	})
	
	// Clean up old tokens after 5 minutes
	go func() {
		time.Sleep(5 * time.Minute)
		r.mu.Lock()
		if session, exists := r.tokenSessions[token]; exists {
			if time.Since(session.CreatedAt) >= 5*time.Minute {
				delete(r.tokenSessions, token)
				logger.Debug("Cleaned up expired token: %s", token)
			}
		}
		r.mu.Unlock()
	}()
}

// ServeHTTP handles GET /vnc/<token> requests to initiate VNC sessions
// Consumes the one-time token and redirects to the actual VNC session
func (r *VNCRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logger.Debug("Request: %s %s from %s", req.Method, req.URL.Path, req.RemoteAddr)
	
	if req.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	path := strings.TrimPrefix(req.URL.Path, "/")
	parts := strings.Split(path, "/")
	
	if len(parts) != 2 || parts[0] != "vnc" {
		http.Error(w, "Invalid path. Use /vnc/<token>", http.StatusBadRequest)
		return
	}
	
	token := parts[1]
	
	// Look up token session
	r.mu.RLock()
	session, exists := r.tokenSessions[token]
	r.mu.RUnlock()
	
	if !exists {
		logger.Error("Invalid token: %s", token)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "Invalid session.")
		return
	}
	
	// Remove token from memory immediately
	r.mu.Lock()
	delete(r.tokenSessions, token)
	r.mu.Unlock()
	
	proxmoxConfig := session.ProxmoxConfig
	
	// Parse VM ID
	vmid, err := strconv.Atoi(proxmoxConfig.VMID)
	if err != nil {
		logger.Error("Invalid VM ID: %s", proxmoxConfig.VMID)
		http.Error(w, "Invalid VM ID", http.StatusBadRequest)
		return
	}
	
	// Create proxy process with the provided configuration
	proxy, err := proxyprocess.NewProxyProcessWithConfig(proxmoxConfig, r.config)
	if err != nil {
		logger.Error("Error creating proxy process: %v", err)
		http.Error(w, fmt.Sprintf("Failed to create proxy: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Generate unique session ID for this connection
	sessionID := generateToken() // Reuse token generation for unique ID
	sessionKey := fmt.Sprintf("%s:%s:%d", sessionID, proxmoxConfig.Node, vmid)
	
	// Set up callbacks for session state changes
	proxy.SetOnConnect(func() {
		r.OnSessionConnected(sessionKey)
	})
	proxy.SetOnDisconnect(func() {
		r.OnSessionDisconnected(sessionKey)
	})
	
	logger.Info("Starting VNC proxy for VM %d on node %s (session key: %s)", vmid, proxmoxConfig.Node, sessionKey)
	
	result, err := proxy.StartVMProxy(vmid)
	if err != nil {
		logger.Error("Error starting VM proxy: %v", err)
		http.Error(w, fmt.Sprintf("Failed to start VNC proxy: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Store recent session with unique key
	r.mu.Lock()
	r.recentSessions[sessionKey] = &RecentSession{
		SessionID: result.SessionID,
		URL:       result.URL,
		NodeName:  proxmoxConfig.Node,
		VMID:      proxmoxConfig.VMID,
		CreatedAt: time.Now(),
		Port:      result.Port,
		Status:    SessionStatusCreated,
	}
	r.mu.Unlock()
	
	logger.Info("VNC proxy started successfully: %s (port: %d)", result.URL, result.Port)
	
	// Redirect to VNC URL
	http.Redirect(w, req, result.URL, http.StatusFound)
}

// handleStatus returns JSON with current session statistics and details
// Requires authorization header for security
func (r *VNCRouter) handleStatus(w http.ResponseWriter, req *http.Request) {
	// Check authorization header
	authHeader := req.Header.Get("Authorization")
	if authHeader != r.config.GetAuthorization() {
		logger.Error("Invalid authorization for status request from %s", req.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	sessions := make([]map[string]interface{}, 0)
	for key, session := range r.recentSessions {
		sessionData := map[string]interface{}{
			"key":        key,
			"session_id": session.SessionID,
			"url":        session.URL,
			"node":       session.NodeName,
			"vmid":       session.VMID,
			"created_at": session.CreatedAt,
			"port":       session.Port,
			"status":     string(session.Status),
			"age":        time.Since(session.CreatedAt).String(),
		}
		
		// Add optional timestamps if they exist
		if session.ConnectedAt != nil {
			sessionData["connected_at"] = *session.ConnectedAt
			sessionData["connected_duration"] = time.Since(*session.ConnectedAt).String()
		}
		if session.EndedAt != nil {
			sessionData["ended_at"] = *session.EndedAt
			if session.ConnectedAt != nil {
				sessionData["session_duration"] = session.EndedAt.Sub(*session.ConnectedAt).String()
			}
		}
		
		sessions = append(sessions, sessionData)
	}
	
	tokenCount := len(r.tokenSessions)
	
	// Count sessions by status
	var created, active, disconnected int
	for _, session := range r.recentSessions {
		switch session.Status {
		case SessionStatusCreated:
			created++
		case SessionStatusActive:
			active++
		case SessionStatusDisconnected:
			disconnected++
		}
	}
	
	response := map[string]interface{}{
		"total_sessions":   len(sessions),
		"pending_tokens":   tokenCount,
		"sessions_created": created,
		"sessions_active":  active,
		"sessions_disconnected": disconnected,
		"sessions":         sessions,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// cleanupSessions runs periodically to remove expired tokens and stale sessions
func (r *VNCRouter) cleanupSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		r.mu.Lock()
		// Clean up old recent sessions (keep for 1 hour after creation or 30 minutes after disconnection)
		for key, session := range r.recentSessions {
			shouldDelete := false
			
			if session.Status == SessionStatusDisconnected && session.EndedAt != nil {
				// Remove disconnected sessions after 30 minutes
				if time.Since(*session.EndedAt) > 30*time.Minute {
					shouldDelete = true
					logger.Debug("Removing disconnected session: %s (ended %v ago)", key, time.Since(*session.EndedAt))
				}
			} else if time.Since(session.CreatedAt) > time.Hour {
				// Remove any session older than 1 hour regardless of status
				shouldDelete = true
				logger.Debug("Removing stale session: %s (created %v ago)", key, time.Since(session.CreatedAt))
			}
			
			if shouldDelete {
				delete(r.recentSessions, key)
			}
		}
		
		// Clean up old token sessions
		for token, session := range r.tokenSessions {
			if time.Since(session.CreatedAt) > 5*time.Minute {
				logger.Debug("Removing expired token: %s", token)
				delete(r.tokenSessions, token)
			}
		}
		r.mu.Unlock()
	}
}

func main() {
	var (
		configPath = flag.String("config", "config.json", "Path to configuration file")
		portOverride = flag.Int("port", 0, "Port to listen on (overrides config)")
	)
	flag.Parse()
	
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Fatal("Failed to load configuration: %v", err)
	}
	
	// Initialize logger with config
	logOutput := "stderr"
	if cfg.LoggingEnabled && cfg.LogFile != "" {
		logOutput = cfg.LogFile
	}
	err = logger.Initialize(cfg.LoggingEnabled, cfg.LoggingLevel, logOutput)
	if err != nil {
		logger.Fatal("Failed to initialize logger: %v", err)
	}
	
	logger.Info("Using configuration: %s", *configPath)
	
	// Use command line port if provided, otherwise use config port
	port := cfg.GetRouterPort()
	if *portOverride != 0 {
		port = *portOverride
	}
	
	logger.Info("Starting VNC Router on port %d", port)
	logger.Info("Router will bind to: %s:%d", cfg.GetRouterIP(), port)
	logger.Info("Public host for VNC URLs: %s", cfg.PublicHost)
	
	router := NewVNCRouter(cfg, *configPath)
	
	go router.cleanupSessions()
	
	// Set up routes
	http.HandleFunc("/create", router.handleCreate)
	http.Handle("/vnc/", router)
	http.HandleFunc("/status", router.handleStatus)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
	
	// Bind to router IP (can be different from public IP)
	addr := fmt.Sprintf("%s:%d", cfg.GetRouterIP(), port)
	logger.Info("VNC Router listening on %s", addr)
	logger.Info("Access the service at http://%s:%d/", cfg.PublicHost, port)
	
	if err := http.ListenAndServe(addr, nil); err != nil {
		logger.Fatal("Failed to start server: %v", err)
	}
}