package vnc

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/ispirto/proxmoxvnc/internal/logger"
	"github.com/ispirto/proxmoxvnc/pkg/api"
)

// SessionType represents the type of VNC session
type SessionType string

const (
	SessionTypeVM  SessionType = "vm"
	SessionTypeLXC SessionType = "lxc"
)

// SessionState represents the current state of a VNC session
type SessionState int

const (
	SessionStateActive SessionState = iota
	SessionStateConnected
	SessionStateDisconnected
	SessionStateClosed
)

// VNCSession represents an active VNC session
type VNCSession struct {
	ID                string
	TargetType        SessionType
	NodeName          string
	VMID              string
	TargetName        string
	Port              int
	URL               string
	CreatedAt         time.Time
	LastUsed          time.Time
	State             SessionState
	ProxyConfig       *ProxyConfig
	Server            *Server
	activeConnections int
	disconnectChan    chan struct{}
	sessionManager    *SessionManager
	cancelFunc        context.CancelFunc
	mutex             sync.RWMutex
}

func (s *VNCSession) UpdateLastUsed() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.LastUsed = time.Now()
}

func (s *VNCSession) WaitForDisconnect(ctx context.Context) bool {
	select {
	case <-s.disconnectChan:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *VNCSession) OnClientConnected() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.activeConnections++
	s.State = SessionStateConnected
	s.LastUsed = time.Now()
}

func (s *VNCSession) OnClientDisconnected() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.activeConnections > 0 {
		s.activeConnections--
	}
	if s.activeConnections == 0 {
		s.State = SessionStateDisconnected
		select {
		case s.disconnectChan <- struct{}{}:
		default:
		}
	}
}

func (s *VNCSession) IsReusable() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.State == SessionStateActive || s.State == SessionStateDisconnected
}

func (s *VNCSession) GetConnectionCount() int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.activeConnections
}

func (s *VNCSession) IsExpired(timeout time.Duration) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return time.Since(s.LastUsed) > timeout
}

func (s *VNCSession) GetTargetKey() string {
	return fmt.Sprintf("%s:%s:%s", s.TargetType, s.NodeName, s.VMID)
}

func (s *VNCSession) Shutdown() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.State = SessionStateClosed
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
	if s.disconnectChan != nil {
		close(s.disconnectChan)
		s.disconnectChan = nil
	}
	if s.Server != nil {
		return s.Server.Stop()
	}
	return nil
}

type SessionCountCallback func(count int)

type SessionManager struct {
	sessions             map[string]*VNCSession
	client               *api.Client
	logger               *logger.Logger
	ctx                  context.Context
	cancelFunc           context.CancelFunc
	cleanupTicker        *time.Ticker
	sessionCountCallback SessionCountCallback
	mutex                sync.RWMutex
	sessionTimeout       time.Duration
	publicHost           string // Public host (IP or domain) for URL generation
	novncPath            string // Path to noVNC files
	tlsCertFile          string // Path to TLS certificate
	tlsKeyFile           string // Path to TLS key
}


func NewSessionManager(client *api.Client, sharedLogger *logger.Logger) *SessionManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	var sessionLogger *logger.Logger
	if sharedLogger != nil {
		sessionLogger = sharedLogger
	} else {
		// Create a logger using global settings
		sessionLogger = logger.CreateComponentLogger("SESSION-MGR")
	}
	
	manager := &SessionManager{
		sessions:       make(map[string]*VNCSession),
		client:         client,
		logger:         sessionLogger,
		ctx:            ctx,
		cancelFunc:     cancel,
		sessionTimeout: 24 * time.Hour,
	}
	
	manager.startCleanupProcess()
	
	if sessionLogger != nil {
		sessionLogger.Info("VNC Session Manager initialized")
	}
	
	return manager
}

func (sm *SessionManager) UpdateClient(client *api.Client) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.logger.Info("Updating session manager client")
	sm.client = client
}

func (sm *SessionManager) SetPublicHost(publicHost string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.publicHost = publicHost
	if sm.logger != nil && publicHost != "" {
		sm.logger.Info("Session manager using configured public host: %s", publicHost)
	}
}

func (sm *SessionManager) SetNoVNCPath(path string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.novncPath = path
	if sm.logger != nil && path != "" {
		sm.logger.Info("Session manager using noVNC path: %s", path)
	}
}

func (sm *SessionManager) SetTLSConfig(certFile, keyFile string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.tlsCertFile = certFile
	sm.tlsKeyFile = keyFile
	if sm.logger != nil && certFile != "" && keyFile != "" {
		sm.logger.Info("Session manager using TLS certificates: cert=%s, key=%s", certFile, keyFile)
	}
}

func (sm *SessionManager) CreateVMSession(vm *api.VM) (*VNCSession, error) {
	var sessionType SessionType
	if vm.Type == "qemu" {
		sessionType = SessionTypeVM
	} else if vm.Type == "lxc" {
		sessionType = SessionTypeLXC
	} else {
		return nil, fmt.Errorf("unsupported VM type: %s", vm.Type)
	}
	
	return sm.CreateSession(context.Background(), sessionType, vm.Node, strconv.Itoa(vm.ID), vm.Name)
}

func (sm *SessionManager) CreateSession(ctx context.Context, sessionType SessionType, nodeName, vmid, targetName string) (*VNCSession, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	targetKey := fmt.Sprintf("%s:%s:%s", sessionType, nodeName, vmid)
	
	// Check for reusable session
	if existingSession := sm.findReusableSession(targetKey); existingSession != nil {
		existingSession.UpdateLastUsed()
		if existingSession.State == SessionStateDisconnected {
			existingSession.mutex.Lock()
			existingSession.State = SessionStateActive
			existingSession.mutex.Unlock()
			if sm.logger != nil {
				sm.logger.Info("Reactivating disconnected VNC session: %s", existingSession.ID)
			}
		}
		return existingSession, nil
	}
	
	// Create new session
	sessionID := fmt.Sprintf("vnc_%d_%s", time.Now().Unix(), targetKey)
	
	session := &VNCSession{
		ID:                sessionID,
		TargetType:        sessionType,
		NodeName:          nodeName,
		VMID:              vmid,
		TargetName:        targetName,
		CreatedAt:         time.Now(),
		LastUsed:          time.Now(),
		State:             SessionStateActive,
		activeConnections: 0,
		disconnectChan:    make(chan struct{}, 1),
		sessionManager:    sm,
	}
	
	// Create and start VNC server with its own logger
	serverLogger := logger.CreateComponentLogger("VNC-SERVER")
	server := NewServerWithHost(serverLogger, sm.publicHost)
	
	// Set custom noVNC path if configured
	if sm.novncPath != "" {
		if err := server.SetNoVNCPath(sm.novncPath); err != nil {
			sm.logger.Error("Failed to set noVNC path: %v", err)
			// Continue with default path
		}
	}
	
	// Set TLS configuration if available
	if sm.tlsCertFile != "" && sm.tlsKeyFile != "" {
		if err := server.SetTLSConfig(sm.tlsCertFile, sm.tlsKeyFile); err != nil {
			sm.logger.Error("Failed to set TLS config: %v", err)
			// Continue without TLS
		}
	}
	
	session.Server = server
	
	var vncURL string
	var err error
	
	// Start appropriate server based on session type
	switch sessionType {
	case SessionTypeVM, SessionTypeLXC:
		vmidInt, _ := strconv.Atoi(vmid)
		vmType := "qemu"
		if sessionType == SessionTypeLXC {
			vmType = "lxc"
		}
		targetVM := &api.VM{
			ID:     vmidInt,
			Node:   nodeName,
			Name:   targetName,
			Type:   vmType,
			Status: "running",
		}
		
		vncURL, err = server.StartVMVNCServerWithSession(sm.client, targetVM, session)
		if err != nil {
			return nil, fmt.Errorf("failed to start VM VNC server: %w", err)
		}
		
	default:
		return nil, fmt.Errorf("unsupported session type: %s", sessionType)
	}
	
	session.Port = server.GetPort()
	session.URL = vncURL
	
	sm.sessions[sessionID] = session
	sm.notifySessionCountChange()
	
	go sm.monitorSessionDisconnect(session)
	
	if sm.logger != nil {
		sm.logger.Info("Created new VNC session: %s for %s:%s", sessionID, nodeName, vmid)
	}
	
	return session, nil
}

func (sm *SessionManager) GetSessionCount() int {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	return len(sm.sessions)
}

func (sm *SessionManager) SetSessionCountCallback(callback SessionCountCallback) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.sessionCountCallback = callback
}

func (sm *SessionManager) notifySessionCountChange() {
	if sm.sessionCountCallback != nil {
		count := len(sm.sessions)
		go sm.sessionCountCallback(count)
	}
}

func (sm *SessionManager) ListSessions() []*VNCSession {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	sessions := make([]*VNCSession, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	
	return sessions
}

func (sm *SessionManager) CloseSession(sessionID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	
	if sm.logger != nil {
		sm.logger.Info("Closing VNC session: %s", sessionID)
	}
	
	err := session.Shutdown()
	delete(sm.sessions, sessionID)
	sm.notifySessionCountChange()
	
	return err
}

func (sm *SessionManager) CloseAllSessions() error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	if sm.logger != nil {
		sm.logger.Info("Closing all VNC sessions: count=%d", len(sm.sessions))
	}
	
	var errors []error
	
	for sessionID, session := range sm.sessions {
		if err := session.Shutdown(); err != nil {
			errors = append(errors, fmt.Errorf("failed to shutdown session %s: %w", sessionID, err))
		}
	}
	
	sm.sessions = make(map[string]*VNCSession)
	sm.notifySessionCountChange()
	
	if len(errors) > 0 {
		return fmt.Errorf("encountered %d errors closing sessions", len(errors))
	}
	
	return nil
}

func (sm *SessionManager) GetSessionByTarget(sessionType SessionType, target string) (*VNCSession, bool) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	for _, session := range sm.sessions {
		if session.TargetType == sessionType && session.TargetName == target {
			return session, true
		}
	}
	
	return nil, false
}

func (sm *SessionManager) CleanupInactiveSessions(maxAge time.Duration) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	var expiredSessions []string
	
	for sessionID, session := range sm.sessions {
		if session.IsExpired(maxAge) {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}
	
	if len(expiredSessions) == 0 {
		return
	}
	
	for _, sessionID := range expiredSessions {
		session := sm.sessions[sessionID]
		
		if sm.logger != nil {
			sm.logger.Info("Cleaning up expired VNC session: %s", sessionID)
		}
		
		session.Shutdown()
		delete(sm.sessions, sessionID)
	}
	
	sm.notifySessionCountChange()
}

func (sm *SessionManager) Shutdown() error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	if sm.logger != nil {
		sm.logger.Info("Shutting down VNC Session Manager")
	}
	
	if sm.cleanupTicker != nil {
		sm.cleanupTicker.Stop()
	}
	
	if sm.cancelFunc != nil {
		sm.cancelFunc()
	}
	
	var shutdownErrors []error
	
	for sessionID, session := range sm.sessions {
		if err := session.Shutdown(); err != nil {
			shutdownErrors = append(shutdownErrors, fmt.Errorf("failed to shutdown session %s: %w", sessionID, err))
		}
	}
	
	sm.sessions = make(map[string]*VNCSession)
	
	if len(shutdownErrors) > 0 {
		return fmt.Errorf("encountered %d errors during shutdown", len(shutdownErrors))
	}
	
	return nil
}

func (sm *SessionManager) findReusableSession(targetKey string) *VNCSession {
	for _, session := range sm.sessions {
		if session.GetTargetKey() == targetKey && session.IsReusable() && !session.IsExpired(sm.sessionTimeout) {
			return session
		}
	}
	return nil
}

func (sm *SessionManager) startCleanupProcess() {
	sm.cleanupTicker = time.NewTicker(30 * time.Minute)
	
	go func() {
		defer sm.cleanupTicker.Stop()
		
		for {
			select {
			case <-sm.ctx.Done():
				return
			case <-sm.cleanupTicker.C:
				sm.cleanupExpiredSessions()
			}
		}
	}()
}

func (sm *SessionManager) cleanupExpiredSessions() {
	sm.CleanupInactiveSessions(sm.sessionTimeout)
}

func (sm *SessionManager) monitorSessionDisconnect(session *VNCSession) {
	for {
		select {
		case <-session.disconnectChan:
			if sm.logger != nil {
				sm.logger.Info("Client disconnected from VNC session: %s", session.ID)
			}
			
			time.Sleep(5 * time.Second)
			
			sm.mutex.Lock()
			if existingSession, exists := sm.sessions[session.ID]; exists {
				if existingSession.GetConnectionCount() == 0 && existingSession.State == SessionStateDisconnected {
					if sm.logger != nil {
						sm.logger.Info("Removing disconnected VNC session: %s", session.ID)
					}
					
					existingSession.Shutdown()
					delete(sm.sessions, session.ID)
					sm.notifySessionCountChange()
				}
			}
			sm.mutex.Unlock()
			
		case <-sm.ctx.Done():
			return
		}
	}
}
