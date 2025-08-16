package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ispirto/proxmoxvnc/internal/logger"
)

// HTTPClient wraps the standard HTTP client with Proxmox-specific functionality
type HTTPClient struct {
	client      *http.Client
	baseURL     string
	authManager *AuthManager
	logger      *logger.Logger
}

// NewHTTPClient creates a new HTTP client wrapper
func NewHTTPClient(client *http.Client, baseURL string, lg *logger.Logger) *HTTPClient {
	return &HTTPClient{
		client:  client,
		baseURL: baseURL,
		logger:  lg,
	}
}

// SetAuthManager sets the authentication manager for the HTTP client
func (h *HTTPClient) SetAuthManager(authManager *AuthManager) {
	h.authManager = authManager
}

// Get performs a GET request to the Proxmox API
func (h *HTTPClient) Get(ctx context.Context, path string, result interface{}) error {
	return h.doRequest(ctx, http.MethodGet, path, nil, result)
}

// GetWithRetry performs a GET request with retry logic
func (h *HTTPClient) GetWithRetry(ctx context.Context, path string, result interface{}, maxRetries int) error {
	var lastErr error
	
	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			h.logger.Debug("Retrying request (attempt %d/%d): %s", i, maxRetries, path)
			time.Sleep(time.Duration(i) * time.Second)
		}
		
		err := h.Get(ctx, path, result)
		if err == nil {
			return nil
		}
		
		lastErr = err
		
		// Check if error is retryable
		if !isRetryableError(err) {
			return err
		}
	}
	
	return fmt.Errorf("request failed after %d retries: %w", maxRetries, lastErr)
}

// Post performs a POST request to the Proxmox API
func (h *HTTPClient) Post(ctx context.Context, path string, data interface{}, result interface{}) error {
	return h.doRequest(ctx, http.MethodPost, path, data, result)
}


// doRequest performs the actual HTTP request
func (h *HTTPClient) doRequest(ctx context.Context, method, path string, data interface{}, result interface{}) error {
	fullURL := h.baseURL + path
	h.logger.Debug("HTTP %s: %s", method, fullURL)
	
	var body io.Reader
	var contentType string
	
	// Prepare request body
	if data != nil {
		if method == http.MethodPost || method == http.MethodPut {
			// For POST/PUT, use form encoding
			formData := url.Values{}
			
			if dataMap, ok := data.(map[string]interface{}); ok {
				for key, value := range dataMap {
					formData.Set(key, fmt.Sprintf("%v", value))
				}
			}
			
			body = strings.NewReader(formData.Encode())
			contentType = "application/x-www-form-urlencoded"
		} else {
			// For other methods, use JSON
			jsonData, err := json.Marshal(data)
			if err != nil {
				return fmt.Errorf("failed to marshal request data: %w", err)
			}
			body = bytes.NewReader(jsonData)
			contentType = "application/json"
		}
	}
	
	// Create request
	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set headers
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", "proxmoxvnc")
	
	// Add authentication
	if err := h.addAuthentication(ctx, req); err != nil {
		return fmt.Errorf("failed to add authentication: %w", err)
	}
	
	// Execute request
	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	
	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h.logger.Debug("Request failed with status %d: %s", resp.StatusCode, string(respBody))
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}
	
	// Parse response if needed
	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}
	
	return nil
}

// addAuthentication adds authentication headers to the request
// Sets PVEAuthCookie for all requests and CSRFPreventionToken for write operations
func (h *HTTPClient) addAuthentication(ctx context.Context, req *http.Request) error {
	// Using ticket authentication
	if h.authManager != nil {
		token, err := h.authManager.GetValidToken(ctx)
		if err != nil {
			return fmt.Errorf("failed to get auth token: %w", err)
		}
		
		// Add cookie for authentication
		req.Header.Set("Cookie", fmt.Sprintf("PVEAuthCookie=%s", token.Ticket))
		
		// Add CSRF token for write operations
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			req.Header.Set("CSRFPreventionToken", token.CSRFToken)
		}
	}
	
	return nil
}

// isRetryableError checks if an error is retryable
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	
	errStr := err.Error()
	
	// Retry on network errors
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "temporary failure") {
		return true
	}
	
	// Retry on certain HTTP status codes
	if strings.Contains(errStr, "status 502") ||
		strings.Contains(errStr, "status 503") ||
		strings.Contains(errStr, "status 504") {
		return true
	}
	
	return false
}