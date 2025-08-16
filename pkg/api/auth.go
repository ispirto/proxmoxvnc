package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ispirto/proxmoxvnc/internal/logger"
)

const (
	// Authentication endpoints
	EndpointAccessTicket = "/access/ticket"
)

// AuthToken represents a Proxmox authentication token
type AuthToken struct {
	Ticket    string    `json:"ticket"`
	CSRFToken string    `json:"csrf_token"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IsValid checks if the token is still valid
func (t *AuthToken) IsValid() bool {
	return t != nil && t.Ticket != "" && time.Now().Before(t.ExpiresAt)
}

// AuthManager handles Proxmox API authentication using username/password
type AuthManager struct {
	httpClient *HTTPClient
	username   string
	password   string
	authToken  *AuthToken
	logger     *logger.Logger
	mu         sync.RWMutex
}

// NewAuthManager creates an auth manager for password authentication
func NewAuthManager(httpClient *HTTPClient, username, password string, lg *logger.Logger) *AuthManager {
	return &AuthManager{
		httpClient: httpClient,
		username:   username,
		password:   password,
		logger:     lg,
	}
}

// EnsureAuthenticated ensures the client is authenticated
func (am *AuthManager) EnsureAuthenticated() error {
	_, err := am.GetValidToken(context.Background())
	return err
}

// GetValidToken returns a valid authentication token, refreshing if expired
func (am *AuthManager) GetValidToken(ctx context.Context) (*AuthToken, error) {
	am.mu.RLock()
	if am.authToken != nil && am.authToken.IsValid() {
		token := am.authToken
		am.mu.RUnlock()
		return token, nil
	}
	am.mu.RUnlock()
	
	// Need to authenticate
	return am.authenticate(ctx)
}

// authenticate performs the authentication flow
func (am *AuthManager) authenticate(ctx context.Context) (*AuthToken, error) {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	// Double-check after acquiring lock
	if am.authToken != nil && am.authToken.IsValid() {
		return am.authToken, nil
	}
	
	am.logger.Debug("Authenticating with Proxmox API: %s", am.username)
	
	// Prepare authentication request
	authURL := EndpointAccessTicket
	
	// Create form data
	formData := url.Values{}
	formData.Set("username", am.username)
	formData.Set("password", am.password)
	
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, 
		am.httpClient.baseURL+authURL, 
		strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create authentication request: %w", err)
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "proxmoxvnc")
	
	// Execute request
	resp, err := am.httpClient.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("authentication failed with status %d: %s", 
			resp.StatusCode, string(body))
	}
	
	// Parse response
	var authResponse struct {
		Data struct {
			Ticket              string `json:"ticket"`
			CSRFPreventionToken string `json:"CSRFPreventionToken"`
			Username            string `json:"username"`
		} `json:"data"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return nil, fmt.Errorf("failed to parse authentication response: %w", err)
	}
	
	// Validate response
	if authResponse.Data.Ticket == "" {
		return nil, fmt.Errorf("authentication failed: no ticket received")
	}
	
	// Create token with 2-hour expiration
	token := &AuthToken{
		Ticket:    authResponse.Data.Ticket,
		CSRFToken: authResponse.Data.CSRFPreventionToken,
		Username:  authResponse.Data.Username,
		ExpiresAt: time.Now().Add(2 * time.Hour),
	}
	
	am.authToken = token
	am.logger.Debug("Authentication successful for user: %s", token.Username)
	
	return token, nil
}

