# ProxmoxVNC Makefile
BINARY_NAME=proxmoxvnc
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}"
GOFILES=$(shell find . -name "*.go" -type f)

# Default target
all: build

# Build the binary
build:
	@echo "Building ${BINARY_NAME}..."
	@go build ${LDFLAGS} -o ${BINARY_NAME} .

# Install binary to $GOPATH/bin
install: build
	@echo "Installing ${BINARY_NAME} to ${GOPATH}/bin..."
	@go install ${LDFLAGS} .

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@go clean
	@rm -f ${BINARY_NAME}
	@rm -rf dist/

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@gofmt -s -w ${GOFILES}

# Lint code
lint:
	@echo "Linting code..."
	@golangci-lint run --timeout 5m

# Run the application
run: build
	@./${BINARY_NAME} -config config.json

# Build for multiple platforms
build-all: build-linux build-darwin build-windows

build-linux:
	@echo "Building for Linux..."
	@GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o dist/${BINARY_NAME}-linux-amd64 .
	@GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o dist/${BINARY_NAME}-linux-arm64 .

build-darwin:
	@echo "Building for macOS..."
	@GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o dist/${BINARY_NAME}-darwin-amd64 .
	@GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o dist/${BINARY_NAME}-darwin-arm64 .

build-windows:
	@echo "Building for Windows..."
	@GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o dist/${BINARY_NAME}-windows-amd64.exe .

# Create release archives
release: build-all
	@echo "Creating release archives..."
	@mkdir -p releases
	@tar czf releases/${BINARY_NAME}-${VERSION}-linux-amd64.tar.gz -C dist ${BINARY_NAME}-linux-amd64
	@tar czf releases/${BINARY_NAME}-${VERSION}-linux-arm64.tar.gz -C dist ${BINARY_NAME}-linux-arm64
	@tar czf releases/${BINARY_NAME}-${VERSION}-darwin-amd64.tar.gz -C dist ${BINARY_NAME}-darwin-amd64
	@tar czf releases/${BINARY_NAME}-${VERSION}-darwin-arm64.tar.gz -C dist ${BINARY_NAME}-darwin-arm64
	@zip -j releases/${BINARY_NAME}-${VERSION}-windows-amd64.zip dist/${BINARY_NAME}-windows-amd64.exe

# Show help
help:
	@echo "Available targets:"
	@echo "  build       - Build the binary"
	@echo "  install     - Build and install to GOPATH/bin"
	@echo "  clean       - Remove build artifacts"
	@echo "  test        - Run tests"
	@echo "  fmt         - Format code"
	@echo "  lint        - Lint code"
	@echo "  run         - Build and run the application"
	@echo "  build-all   - Build for all platforms"
	@echo "  release     - Create release archives"
	@echo "  help        - Show this help message"

.PHONY: all build install clean test fmt lint run build-all build-linux build-darwin build-windows release help