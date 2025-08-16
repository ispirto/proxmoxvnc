package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ispirto/proxmoxvnc/internal/logger"
	"github.com/ispirto/proxmoxvnc/pkg/api/interfaces"
)

// Client is a Proxmox API client
type Client struct {
	httpClient  *HTTPClient
	authManager *AuthManager
	logger      *logger.Logger
	baseURL     string
	user        string
}

// NewClient creates a new Proxmox API client
func NewClient(config interfaces.Config, options ...ClientOption) (*Client, error) {
	// Apply options
	opts := defaultOptions()
	for _, option := range options {
		option(opts)
	}
	
	// Validate input
	if config.GetAddr() == "" {
		return nil, fmt.Errorf("proxmox address cannot be empty")
	}
	
	// Construct base URL
	baseURL := strings.TrimRight(config.GetAddr(), "/")
	if !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	
	// Remove /api2/json suffix if present
	serverBaseURL := strings.TrimSuffix(baseURL, "/api2/json")
	
	opts.Logger.Debug("Proxmox server URL: %s", serverBaseURL)
	opts.Logger.Debug("Proxmox API base URL: %s", serverBaseURL+"/api2/json")
	
	// Configure TLS
	tlsConfig := &tls.Config{InsecureSkipVerify: config.GetInsecure()}
	
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("failed to get default transport")
	}
	
	transport = transport.Clone()
	transport.TLSClientConfig = tlsConfig
	
	// Create HTTP client
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
	
	// Validate port presence
	if !strings.Contains(serverBaseURL, ":") {
		return nil, fmt.Errorf("missing port in address %s", serverBaseURL)
	}
	
	// Format credentials with realm
	userWithRealm := fmt.Sprintf("%s@%s", config.GetUser(), config.GetRealm())
	
	// Create HTTP client wrapper
	httpClientWrapper := NewHTTPClient(httpClient, serverBaseURL+"/api2/json", opts.Logger)
	
	// Create auth manager (password authentication only)
	authManager := NewAuthManager(httpClientWrapper, userWithRealm, config.GetPassword(), opts.Logger)
	
	// Create client
	client := &Client{
		httpClient:  httpClientWrapper,
		authManager: authManager,
		logger:      opts.Logger,
		baseURL:     serverBaseURL,
		user:        config.GetUser(),
	}
	
	// Set auth manager in HTTP client
	httpClientWrapper.SetAuthManager(authManager)
	
	// Test authentication
	if err := authManager.EnsureAuthenticated(); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	
	opts.Logger.Debug("Proxmox API client initialized successfully")
	
	return client, nil
}

// Get makes a GET request to the Proxmox API
func (c *Client) Get(path string, result *map[string]interface{}) error {
	c.logger.Debug("API GET: %s", path)
	return c.httpClient.GetWithRetry(context.Background(), path, result, 3)
}

// Post makes a POST request to the Proxmox API
func (c *Client) Post(path string, data interface{}) error {
	c.logger.Debug("API POST: %s", path)
	
	var postData interface{}
	if data != nil {
		var ok bool
		postData, ok = data.(map[string]interface{})
		if !ok {
			return fmt.Errorf("data must be of type map[string]interface{}")
		}
	}
	
	return c.httpClient.Post(context.Background(), path, postData, nil)
}

// PostWithResponse makes a POST request and returns the response
func (c *Client) PostWithResponse(path string, data interface{}, result *map[string]interface{}) error {
	c.logger.Debug("API POST with response: %s", path)
	
	var postData interface{}
	if data != nil {
		var ok bool
		postData, ok = data.(map[string]interface{})
		if !ok {
			return fmt.Errorf("data must be of type map[string]interface{}")
		}
	}
	
	return c.httpClient.Post(context.Background(), path, postData, result)
}


// GetBaseURL returns the base URL of the Proxmox API
func (c *Client) GetBaseURL() string {
	return c.baseURL
}

// GetAuthToken returns the authentication token (for WebSocket connections)
func (c *Client) GetAuthToken() string {
	// For ticket-based authentication, return the cookie format
	if c.authManager != nil {
		ctx := context.Background()
		token, err := c.authManager.GetValidToken(ctx)
		if err == nil && token != nil {
			return fmt.Sprintf("PVEAuthCookie=%s", token.Ticket)
		}
	}
	
	return ""
}