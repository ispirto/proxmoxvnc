// Package logger provides a simple logging system using the standard log package
package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// Level represents the logging level
type Level int

const (
	DEBUG Level = iota
	INFO
	ERROR
)

// Logger wraps the standard log.Logger with level support
type Logger struct {
	logger    *log.Logger
	level     Level
	component string
}

// Global logger instance and output destination
var (
	Default       *Logger
	globalOutput  *os.File
	globalLevel   Level = INFO
	globalEnabled bool  = true
)

// Initialize sets up the global logger with the specified configuration
// output can be "stdout", "stderr", or a file path
func Initialize(enabled bool, levelStr string, output string) error {
	level := ParseLevel(levelStr)
	globalLevel = level
	globalEnabled = enabled
	
	if !enabled {
		// Create a no-op logger that discards everything
		Default = &Logger{
			logger: log.New(os.Stderr, "", 0),
			level:  ERROR + 1, // Higher than any level, so nothing gets logged
		}
		globalOutput = nil
		return nil
	}
	
	var writer *os.File
	switch output {
	case "stdout":
		writer = os.Stdout
	case "stderr", "":
		writer = os.Stderr
	default:
		// It's a file path
		// Create logs directory if needed
		if err := os.MkdirAll("logs", 0755); err != nil {
			return fmt.Errorf("failed to create logs directory: %w", err)
		}
		
		file, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		writer = file
	}
	
	globalOutput = writer
	Default = &Logger{
		logger:    log.New(writer, "", log.Ldate|log.Ltime),
		level:     level,
		component: "ROUTER",
	}
	
	return nil
}

// ParseLevel converts a string to a Level
func ParseLevel(levelStr string) Level {
	switch strings.ToLower(levelStr) {
	case "debug":
		return DEBUG
	case "error":
		return ERROR
	default:
		return INFO
	}
}

// CreateLogger creates a new logger instance (for components that need their own)
func CreateLogger(enabled bool, level Level, component string) *Logger {
	if !enabled {
		return &Logger{
			logger:    log.New(os.Stderr, "", 0),
			level:     ERROR + 1, // No-op logger
			component: component,
		}
	}
	
	// Use the global output if available
	output := globalOutput
	if output == nil {
		output = os.Stderr
	}
	
	return &Logger{
		logger:    log.New(output, "", log.Ldate|log.Ltime),
		level:     level,
		component: component,
	}
}

// CreateComponentLogger creates a logger using global settings but with a different component name
func CreateComponentLogger(component string) *Logger {
	return CreateLogger(globalEnabled, globalLevel, component)
}

// formatWithComponent adds component prefix if present
func (l *Logger) formatWithComponent(level, format string, args ...interface{}) string {
	message := fmt.Sprintf(format, args...)
	if l.component != "" {
		return fmt.Sprintf("[%s] [%s] %s", l.component, level, message)
	}
	return fmt.Sprintf("[%s] %s", level, message)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	if l == nil {
		return
	}
	if l.level <= DEBUG {
		l.logger.Output(2, l.formatWithComponent("DEBUG", format, args...))
	}
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	if l == nil {
		return
	}
	if l.level <= INFO {
		l.logger.Output(2, l.formatWithComponent("INFO", format, args...))
	}
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	if l == nil {
		return
	}
	if l.level <= ERROR {
		l.logger.Output(2, l.formatWithComponent("ERROR", format, args...))
	}
}

// Fatal logs an error message and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	if l == nil {
		log.Fatalf("[FATAL] "+format, args...)
		return
	}
	l.logger.Fatalf(l.formatWithComponent("FATAL", format, args...))
}

// Global convenience functions that use the default logger

func Debug(format string, args ...interface{}) {
	if Default != nil {
		Default.Debug(format, args...)
	}
}

func Info(format string, args ...interface{}) {
	if Default != nil {
		Default.Info(format, args...)
	}
}

func Error(format string, args ...interface{}) {
	if Default != nil {
		Default.Error(format, args...)
	}
}

func Fatal(format string, args ...interface{}) {
	if Default != nil {
		Default.Fatal(format, args...)
	} else {
		log.Fatalf("[FATAL] "+format, args...)
	}
}