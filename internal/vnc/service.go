package vnc

import (
	"fmt"
	"time"

	"github.com/ispirto/proxmoxvnc/internal/logger"
	"github.com/ispirto/proxmoxvnc/pkg/api"
)

// Service provides VNC connection management
type Service struct {
	client         *api.Client
	sessionManager *SessionManager
	logger         *logger.Logger
}


// NewService creates a new VNC service with the given API client and optional logger
func NewService(client *api.Client, sharedLogger *logger.Logger) *Service {
	var vncLogger *logger.Logger
	
	if sharedLogger != nil {
		vncLogger = sharedLogger
	} else {
		// Create a logger using global settings
		vncLogger = logger.CreateComponentLogger("VNC-SERVICE")
	}
	
	vncLogger.Info("Creating new VNC service with session management")
	
	// Create a separate logger for session manager using same settings but different component
	sessionLogger := logger.CreateComponentLogger("SESSION-MGR")
	
	return &Service{
		client:         client,
		sessionManager: NewSessionManager(client, sessionLogger),
		logger:         vncLogger,
	}
}

func (s *Service) UpdateClient(client *api.Client) {
	s.logger.Info("Updating VNC service client")
	
	if s.sessionManager != nil {
		s.logger.Info("Closing all existing VNC sessions due to client update")
		s.sessionManager.CloseAllSessions()
	}
	
	s.client = client
	s.sessionManager.UpdateClient(client)
}

func (s *Service) SetPublicHost(publicHost string) {
	if s.sessionManager != nil {
		s.sessionManager.SetPublicHost(publicHost)
	}
}

func (s *Service) SetNoVNCPath(path string) {
	if s.sessionManager != nil {
		s.sessionManager.SetNoVNCPath(path)
	}
}

func (s *Service) SetTLSConfig(certFile, keyFile string) {
	if s.sessionManager != nil {
		s.sessionManager.SetTLSConfig(certFile, keyFile)
	}
}



func (s *Service) ConnectToVMEmbedded(vm *api.VM) (string, *VNCSession, error) {
	s.logger.Info("Starting embedded VNC connection for VM: %s (ID: %d, Type: %s, Node: %s)", 
		vm.Name, vm.ID, vm.Type, vm.Node)
	
	session, err := s.sessionManager.CreateVMSession(vm)
	if err != nil {
		s.logger.Error("Failed to create VM session for %s: %v", vm.Name, err)
		return "", nil, fmt.Errorf("failed to create VM session: %w", err)
	}
	
	s.logger.Info("VM VNC session ready: %s (Port: %d, Session: %s)", 
		vm.Name, session.Port, session.ID)
	s.logger.Info("VNC client ready for VM %s (Session: %s)", vm.Name, session.ID)
	
	return session.URL, session, nil
}

func (s *Service) ListActiveSessions() []*VNCSession {
	sessions := s.sessionManager.ListSessions()
	s.logger.Debug("Retrieved %d active VNC sessions", len(sessions))
	return sessions
}

func (s *Service) GetActiveSessionCount() int {
	return s.sessionManager.GetSessionCount()
}

func (s *Service) SetSessionCountCallback(callback func(int)) {
	s.sessionManager.SetSessionCountCallback(callback)
}

func (s *Service) CloseSession(sessionID string) error {
	s.logger.Info("Closing VNC session: %s", sessionID)
	
	err := s.sessionManager.CloseSession(sessionID)
	if err != nil {
		s.logger.Error("Failed to close VNC session %s: %v", sessionID, err)
		return err
	}
	
	s.logger.Info("VNC session closed successfully: %s", sessionID)
	return nil
}

func (s *Service) CloseAllSessions() error {
	s.logger.Info("Closing all VNC sessions")
	
	err := s.sessionManager.CloseAllSessions()
	if err != nil {
		s.logger.Error("Failed to close all VNC sessions: %v", err)
		return err
	}
	
	s.logger.Info("All VNC sessions closed successfully")
	return nil
}

func (s *Service) GetSessionByTarget(sessionType SessionType, target string) (*VNCSession, bool) {
	session, exists := s.sessionManager.GetSessionByTarget(sessionType, target)
	if exists {
		s.logger.Debug("Found existing VNC session for %s %s: %s", 
			sessionType, target, session.ID)
	} else {
		s.logger.Debug("No existing VNC session found for %s %s", sessionType, target)
	}
	
	return session, exists
}

func (s *Service) CleanupInactiveSessions(maxAge time.Duration) {
	s.sessionManager.CleanupInactiveSessions(maxAge)
}

