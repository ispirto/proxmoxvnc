package api

import "newproxmoxvnc/internal/logger"

// ClientOptions holds optional configuration for the client
type ClientOptions struct {
	Logger *logger.Logger
}

// ClientOption is a function that configures ClientOptions
type ClientOption func(*ClientOptions)

// WithLogger sets a custom logger for the client
func WithLogger(lg *logger.Logger) ClientOption {
	return func(opts *ClientOptions) {
		opts.Logger = lg
	}
}

// defaultOptions returns the default client options
func defaultOptions() *ClientOptions {
	return &ClientOptions{
		Logger: logger.CreateComponentLogger("API"),
	}
}