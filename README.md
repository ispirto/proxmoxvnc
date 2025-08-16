# ProxmoxVNC

A secure, token-based VNC proxy service for Proxmox Virtual Environment that provides web-based console access to VMs and containers while completely isolating Proxmox infrastructure from end users.

## Table of Contents

- [Key Features](#key-features)
- [Architecture Overview](#architecture-overview)
- [Proxmox Infrastructure Isolation](#proxmox-infrastructure-isolation)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage Guide](#usage-guide)
- [API Reference](#api-reference)
- [Security Features](#security-features)
- [How It Works](#how-it-works)
- [Session Management](#session-management)
- [Logging](#logging)
- [Technical Details](#technical-details)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Key Features

- 🔐 **Token-Based Authentication** - One-time tokens for secure VNC access
- 🛡️ **Complete Proxmox Isolation** - No exposure of Proxmox credentials, IPs, or cookies to end users
- 🌐 **Pure Web-Based** - Uses vanilla noVNC v1.6.0, no browser plugins required
- 🔑 **Dynamic Credentials** - Proxmox connection details provided per-request via API
- 📦 **Universal VM Support** - Works with both QEMU VMs and LXC containers
- 🔄 **Automatic Cleanup** - Sessions and tokens auto-expire with configurable timeouts
- 📝 **Comprehensive Logging** - Multi-level logging with debug, info, and error modes
- 🚀 **High Performance** - Concurrent session support with port pooling

## Architecture Overview

```
┌─────────────┐         ┌─────────────────┐         ┌──────────────┐
│  API Client │ ──1──▶  │   VNC Router    │         │   Proxmox    │
│  (Backend)  │         │   Port: 9999    │         │   Server     │
└─────────────┘         └─────────────────┘         └──────────────┘
      │                         │                           ▲
      │                         │                           │
   2. POST /create              │                           │
   (with auth token)            │                        5. Auth &
      │                         │                        VNC Ticket
      ▼                         │                           │
┌─────────────┐                 │                           │
│    Token    │                 │                    ┌──────────────┐
│ a1b2c3d4... │                 ├────────────────────│ Proxy Process│
└─────────────┘                 │                    └──────────────┘
      │                         │                           │
   3. Share with                │                           │
      end user                  │                     ┌──────────────┐
      │                         ├─────────────────────│ VNC Session  │
      ▼                         │                     │ Random Port  │
┌─────────────┐                 │                     └──────────────┘
│  End User   │ ──4──▶         │                           │
│   Browser   │  GET /vnc/token │                     ┌──────────────┐
└─────────────┘                 └─────────────────────│  WebSocket   │
      │                                               │    Proxy     │
      │                                               └──────────────┘
      │                                                     │
      └──────────────── 6. VNC Session ────────────────────┘
                    (noVNC in browser)
```

### Data Flow

1. **API Client** authenticates with router using authorization token
2. **API Client** sends Proxmox credentials and VM details to `/create`
3. **Router** generates one-time token and stores credentials in memory
4. **End User** accesses `/vnc/<token>` with browser
5. **Proxy Process** authenticates with Proxmox using provided credentials
6. **End User** gets redirected to isolated VNC session

## Proxmox Infrastructure Isolation

### Complete Credential Isolation

ProxmoxVNC ensures that end users **NEVER** have access to:

- **Proxmox Authentication Cookies** (`PVEAuthCookie`)
  - Used only in server-to-server communication
  - Never sent to client browsers
  - Isolated within the proxy process

- **Proxmox API Credentials**
  - Username/password never exposed to end users
  - Stored temporarily in router memory only
  - Deleted immediately after token consumption

- **Proxmox Server Details**
  - Server IP addresses remain hidden
  - Node names not exposed to end users
  - Port numbers concealed from clients

### Security Boundaries

```
┌──────────────────────────────────────────────────────────┐
│                    PUBLIC ZONE (End Users)               │
│                                                          │
│  • Receives: One-time access token                      │
│  • Sees: Public router IP and VNC session port          │
│  • Gets: VNC protocol stream only                       │
│  • No access to: Proxmox cookies, credentials, or IPs   │
│                                                          │
├──────────────────────────────────────────────────────────┤
│                  PROXY ZONE (VNC Router)                 │
│                                                          │
│  • Holds: Temporary session credentials (5 min max)     │
│  • Manages: Token generation and validation             │
│  • Controls: Session lifecycle and cleanup              │
│                                                          │
├──────────────────────────────────────────────────────────┤
│                PRIVATE ZONE (Backend Only)               │
│                                                          │
│  • Proxmox server communication                         │
│  • PVEAuthCookie handling                               │
│  • Direct API authentication                            │
│  • Never exposed to public zone                         │
└──────────────────────────────────────────────────────────┘
```

### What End Users Receive

End users only receive:
1. **One-time token** - Single-use, expires after consumption
2. **VNC session URL** - Points to the proxy, not Proxmox
3. **VNC parameters** via mandatory.json:
   - `autoconnect`: true
   - `reconnect`: true
   - `password`: VNC-specific password (not Proxmox password)
   - `path`: vnc-proxy
   - `resize`: scale

### Authentication Flow Isolation

```
API Client                Router                  Proxmox
    │                        │                        │
    ├──Credentials──────────▶│                        │
    │                        ├──Authenticate─────────▶│
    │                        │◀──PVEAuthCookie────────┤
    │◀──Token────────────────┤                        │
    │                        │                        │
End User                     │                        │
    │                        │                        │
    ├──Token────────────────▶│                        │
    │                        ├──Use Cookie───────────▶│
    │◀──VNC Stream───────────┤◀──VNC Stream──────────┤
    │                        │                        │
    │ (Never sees cookie)    │                        │
```

## Installation

### Prerequisites

- Go 1.21 or higher (only for building from source)
- Access to Proxmox VE server(s)
- Network connectivity between proxy and Proxmox
- Public IP for client access

### Method 1: Download Pre-built Binary (Recommended)

Download the latest release for your platform:

```bash
# Linux (amd64)
curl -L https://github.com/ispirto/proxmoxvnc/releases/latest/download/proxmoxvnc-linux-amd64.tar.gz | tar xz
sudo mv proxmoxvnc /usr/local/bin/

# macOS (Apple Silicon)
curl -L https://github.com/ispirto/proxmoxvnc/releases/latest/download/proxmoxvnc-darwin-arm64.tar.gz | tar xz
sudo mv proxmoxvnc /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/ispirto/proxmoxvnc/releases/latest/download/proxmoxvnc-darwin-amd64.tar.gz | tar xz
sudo mv proxmoxvnc /usr/local/bin/
```

### Method 2: Install with Go

```bash
go install github.com/ispirto/proxmoxvnc@latest
```

### Method 3: Build from Source

```bash
# Clone the repository
git clone https://github.com/ispirto/proxmoxvnc.git
cd proxmoxvnc

# Build with make
make build

# Or build directly with go
go build -o proxmoxvnc

# Install to system (optional)
sudo make install
```

### Quick Start

```bash
# Download example configuration
curl -L https://raw.githubusercontent.com/ispirto/proxmoxvnc/main/config.json.example -o config.json

# Edit config.json with your settings
vim config.json

# Start the router
proxmoxvnc -config config.json

# Or if running from source
./proxmoxvnc -config config.json
```

### Running as a Service (systemd)

Create a systemd service file:

```bash
sudo tee /etc/systemd/system/proxmoxvnc.service > /dev/null <<EOF
[Unit]
Description=ProxmoxVNC Router Service
After=network.target

[Service]
Type=simple
User=proxmoxvnc
Group=proxmoxvnc
WorkingDirectory=/etc/proxmoxvnc
ExecStart=/usr/local/bin/proxmoxvnc -config /etc/proxmoxvnc/config.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create user and directories
sudo useradd -r -s /bin/false proxmoxvnc
sudo mkdir -p /etc/proxmoxvnc
sudo cp config.json /etc/proxmoxvnc/
sudo chown -R proxmoxvnc:proxmoxvnc /etc/proxmoxvnc

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable proxmoxvnc
sudo systemctl start proxmoxvnc
```

## Configuration

### Router Configuration (config.json)

```json
{
  "authorization": "your-secret-authorization-token-here",
  "logging_enabled": true,
  "logging_level": "info",
  "log_file": "logs/proxy.log",
  "public_ip": "203.0.113.10",
  "router_ip": "0.0.0.0",
  "router_port": 9999,
  "novnc_path": "./internal/vnc/novnc"
}
```

| Field | Description | Required | Default |
|-------|-------------|----------|---------|
| `authorization` | Secret token for API authentication. Clients must provide this in the Authorization header | Yes | - |
| `logging_enabled` | Enable or disable logging output | No | true |
| `logging_level` | Log verbosity level: `debug`, `info`, or `error` | No | info |
| `log_file` | Where to write logs: `stderr`, `stdout`, or a file path (e.g., `logs/proxy.log`) | No | stderr |
| `public_ip` | Public IP address that clients will use to access VNC sessions. This appears in URLs given to end users | Yes | - |
| `router_ip` | IP address to bind the router service to. Use `0.0.0.0` for all interfaces, `127.0.0.1` for localhost only | No | 0.0.0.0 |
| `router_port` | Port number for the router service to listen on | No | 9999 |
| `novnc_path` | Path to noVNC static files directory (can be relative or absolute) | No | ./internal/vnc/novnc |

### Configuration Examples

#### Basic Configuration
```json
{
  "authorization": "your-secret-token-here",
  "logging_enabled": true,
  "logging_level": "info",
  "public_ip": "203.0.113.10"
}
```

#### Behind NAT/Firewall
```json
{
  "authorization": "your-secret-token-here",
  "logging_enabled": true,
  "logging_level": "info",
  "log_file": "logs/proxy.log",
  "public_ip": "203.0.113.10",  // External NAT IP
  "router_ip": "192.168.1.100",  // Internal private IP
  "router_port": 9999
}
```

#### Localhost Only (for reverse proxy)
```json
{
  "authorization": "your-secret-token-here",
  "logging_enabled": true,
  "logging_level": "info",
  "public_ip": "proxy.example.com",  // Reverse proxy domain
  "router_ip": "127.0.0.1",          // Bind to localhost only
  "router_port": 9999
}
```

### Security Note

- Use strong, random authorization tokens (minimum 32 characters)
- Rotate authorization tokens regularly
- Keep config.json readable only by the service user

## Usage Guide

### Step 1: Start the Router Service

```bash
# Start with configuration file
./proxmoxvnc -config config.json

# Override port via command line
./proxmoxvnc -config config.json -port 8888
```

### Step 2: Create a VNC Session Token

Your backend application makes an authenticated API call:

```bash
curl -X POST http://203.0.113.10:9999/create \
  -H "Authorization: your-secret-authorization-token-here" \
  -F 'params={
    "hostname": "192.168.1.100",
    "port": "8006",
    "node": "pve",
    "username": "vncuser@pve",
    "password": "proxmox-password",
    "vmid": "100"
  }'
```

**Parameters:**

| Field | Description | Example |
|-------|-------------|---------|
| `hostname` | Proxmox server IP or hostname | 192.168.1.100 |
| `port` | Proxmox API port | 8006 |
| `node` | Proxmox node name | pve |
| `username` | Proxmox username with realm | vncuser@pve |
| `password` | Proxmox password | secretpass |
| `vmid` | Virtual machine ID | 100 |

**Success Response:**
```json
{
  "status": "success",
  "token": "a1b2c3d4e5f6g7h8i9j0"
}
```

**Error Response:**
- `401 Unauthorized`: Invalid or missing authorization token

### Step 3: Access VNC Session

Share the token URL with the end user:

```
http://203.0.113.10:9999/vnc/a1b2c3d4e5f6g7h8i9j0
```

When accessed:
1. Token is validated and immediately consumed (one-time use)
2. Proxy connects to Proxmox with provided credentials
3. User is redirected to VNC session
4. Token is deleted from memory

### Step 4: Monitor Active Sessions

```bash
curl http://203.0.113.10:9999/status \
  -H "Authorization: your-secret-authorization-token-here"
```

Response:
```json
{
  "total_sessions": 2,
  "pending_tokens": 5,
  "sessions_created": 0,
  "sessions_active": 1,
  "sessions_disconnected": 1,
  "sessions": [
    {
      "key": "vm:pve:100",
      "session_id": "vnc_1234567890_vm:pve:100",
      "url": "http://203.0.113.10:8080/",
      "node": "pve",
      "vmid": "100",
      "created_at": "2024-01-10T10:30:45Z",
      "connected_at": "2024-01-10T10:31:00Z",
      "connected_duration": "4m45s",
      "port": 8080,
      "status": "active",
      "age": "5m30s"
    }
  ]
}
```

## API Reference

### POST /create

Create a new VNC session token.

**Headers:**
- `Authorization: <your-secret-token>` (required)

**Body (multipart/form-data):**
- `params`: JSON object with Proxmox connection details

**Response:**
- `200 OK`: Token created successfully with JSON body
- `401 Unauthorized`: Invalid or missing authorization token
- `405 Method Not Allowed`: Wrong HTTP method

### GET /vnc/<token>

Access VNC session with one-time token.

**Parameters:**
- `token`: One-time access token

**Response:**
- `302 Found`: Redirects to VNC session
- `200 OK`: "Invalid session." if token is invalid

### GET /

Root endpoint (security feature).

**Response:**
- `401 Unauthorized`: Always returns unauthorized

### GET /status

View system status and active sessions.

**Headers:**
- `Authorization: <your-secret-token>` (required)

**Response:**
- `200 OK`: Returns JSON with session details and statistics
- `401 Unauthorized`: Invalid or missing authorization token

## Security Features

### Token Security

- **Cryptographically Random**: 20 hex characters (80 bits of entropy)
- **One-Time Use**: Token deleted immediately upon consumption
- **Auto-Expiration**: Unused tokens expire after 5 minutes
- **Memory Storage**: Tokens never written to disk

### Session Security

- **Isolated Processes**: Each session runs in its own process
- **Automatic Cleanup**: Sessions cleaned up on disconnect
- **Port Isolation**: Each session gets unique port
- **No State Persistence**: Nothing saved between restarts

### Network Security

- **TLS Support**: Proxmox connections use HTTPS
- **WebSocket Security**: Encrypted VNC traffic
- **No Direct Access**: Clients can't connect directly to Proxmox
- **IP Whitelisting**: Can be implemented at firewall level

## How It Works

### 1. Token Creation Phase

```
API Client → Router
   │
   ├─ Validates authorization header
   ├─ Parses Proxmox credentials
   ├─ Generates random token
   ├─ Stores in memory (5 min TTL)
   └─ Returns token to client
```

### 2. Token Consumption Phase

```
End User → Router
   │
   ├─ Validates token exists
   ├─ Retrieves stored credentials
   ├─ Deletes token (one-time use)
   ├─ Creates proxy process
   └─ Redirects to VNC session
```

### 3. VNC Session Phase

```
Browser → Proxy → Proxmox
   │        │        │
   ├────────┼────────┤ WebSocket connection
   │        ├────────▶ Authenticates with API
   │        ◀──────── Gets VNC ticket
   │        ├────────▶ Opens VNC WebSocket
   ◀────────┤         Relays VNC protocol
```

## Session Management

### Lifecycle

1. **Created**: New session on token validation
2. **Active**: While client connected
3. **Disconnected**: After client disconnects
4. **Cleanup**: Automatic after timeout or manual cleanup
5. **Expiration**: After 1 hour if stale

### Resource Management

- **Memory**: ~10MB per active session
- **CPU**: Minimal (WebSocket relay only)
- **Cleanup**: Automatic every 5 minutes

### Session Reuse

Sessions can be reused for the same VM if:
- Previous session is active or disconnected < 24 hours ago
- Same node and VM ID
- Session still in memory

## Logging

### Configuration

Set in config.json:
```json
{
  "logging_enabled": true,
  "logging_level": "debug",
  "log_file": "logs/proxy.log"  // Optional: defaults to stderr
}
```

### Log Levels

- **debug**: Verbose output for troubleshooting
- **info**: Normal operational messages
- **error**: Error conditions only

### Log Output

Logs can be written to:
- **stderr** (default) - Standard error output
- **stdout** - Standard output
- **file** - Any file path (e.g., `logs/proxy.log`)

### Component Prefixes

Each log entry includes a component prefix to identify its source:

| Prefix | Component | Source File | Description |
|--------|-----------|-------------|-------------|
| `[ROUTER]` | HTTP Router | `main.go` | Main HTTP server handling `/create`, `/vnc/<token>`, and `/status` endpoints |
| `[PROXY]` | Proxy Process | `internal/proxyprocess/proxyprocess.go` | Manages the lifecycle of VNC proxy connections for VMs |
| `[API]` | API Client | `pkg/api/*.go` (client.go, auth.go, http.go, vm.go, vm_vnc.go) | Handles all communication with Proxmox API (authentication, VM info, VNC tickets) |
| `[VNC-SERVICE]` | VNC Service | `internal/vnc/service.go` | High-level orchestrator for VNC operations |
| `[SESSION-MGR]` | Session Manager | `internal/vnc/session_manager.go` | Manages VNC session lifecycle, port allocation, and cleanup |
| `[VNC-SERVER]` | VNC Server | `internal/vnc/server.go` | HTTP server that serves noVNC files and handles WebSocket endpoints |
| `[WS-PROXY]` | WebSocket Proxy | `internal/vnc/proxy.go` | Bidirectional WebSocket relay between noVNC client and Proxmox VNC |
| `[PROXY-CFG]` | Proxy Config | `internal/vnc/proxy.go` (CreateVMProxyConfig function) | Handles VNC proxy configuration and ticket generation |

### Example Output

```
2025/08/16 13:08:45 [ROUTER] [INFO] Starting VNC Router on port 9999
2025/08/16 13:08:52 [ROUTER] [INFO] Created token a1b2c3d4e5 for VM 100 on node pve
2025/08/16 13:08:55 [PROXY] [INFO] Starting VNC proxy for VM 100 on node pve
2025/08/16 13:08:55 [API] [DEBUG] Authenticating with Proxmox API: vncuser@pve
2025/08/16 13:08:56 [API] [DEBUG] API GET: /nodes/pve/qemu/100/status/current
2025/08/16 13:08:56 [VNC-SERVICE] [INFO] Creating new VNC service with session management
2025/08/16 13:08:56 [SESSION-MGR] [INFO] Created new VNC session: vnc_1234567890_vm:pve:100
2025/08/16 13:08:56 [VNC-SERVER] [INFO] HTTP server started successfully on port 8080
2025/08/16 13:08:56 [WS-PROXY] [INFO] WebSocket connection established with client
2025/08/16 13:08:56 [WS-PROXY] [DEBUG] Successfully connected to Proxmox VNC websocket
2025/08/16 13:09:45 [WS-PROXY] [INFO] WebSocket proxy session ended for VM-100
2025/08/16 13:09:45 [SESSION-MGR] [INFO] Client disconnected from VNC session: vnc_1234567890_vm:pve:100
```

### Understanding the Flow

Following the component prefixes helps trace the execution flow:

1. `[ROUTER]` - Receives HTTP requests and manages tokens
2. `[PROXY]` - Creates and manages the proxy process for a VM
3. `[API]` - Authenticates and communicates with Proxmox
4. `[VNC-SERVICE]` - Orchestrates the VNC connection setup
5. `[SESSION-MGR]` - Manages the session lifecycle
6. `[VNC-SERVER]` - Serves noVNC and handles HTTP/WebSocket
7. `[WS-PROXY]` - Relays data between client and Proxmox
8. `[PROXY-CFG]` - Configures proxy parameters

### Debug Mode

Enable debug logging for detailed troubleshooting:

```json
{
  "logging_level": "debug"
}
```

This will show:
- All API requests and responses
- WebSocket connection details
- Token lifecycle events
- Proxmox communication

### Proxmox Requirements

#### API User Permissions

Create a dedicated user for VNC access:

```bash
# Create user
pveum user add vncproxy@pve

# Set password
pveum passwd vncproxy@pve

# Grant permissions
pveum aclmod / -user vncproxy@pve -role PVEVMUser
```

Required permissions:
- `VM.Console` - Access VNC console
- `VM.Audit` - View VM configuration

#### Network Configuration

Open ports:
- Router → Proxmox: TCP 8006 (API)
- Router → Proxmox: TCP 5900-5999 (VNC)
- Clients → Router: TCP 9999 (API)

### Client Requirements

- Modern web browser with:
  - JavaScript enabled
  - WebSocket support
  - HTML5 Canvas support

Tested browsers:
- Chrome/Chromium 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Technical Details

### Component Architecture

```
main.go
├── Token Management (in-memory store)
├── HTTP Router (standard net/http)
└── Session Manager

internal/
├── config/          # Configuration management
│   └── config.go    # Config & ProxmoxConfig structs
├── proxyprocess/    # Proxy process management
│   └── proxyprocess.go
├── vnc/            # VNC server components
│   ├── service.go  # VNC service manager
│   ├── server.go   # HTTP/WebSocket server
│   ├── proxy.go    # WebSocket proxy
│   └── session_manager.go # Session lifecycle management
└── logger/         # Logging system
    └── logger.go   # Component-based logging

pkg/api/           # Proxmox API client
├── client.go      # Main API client
├── auth.go        # Authentication
├── http.go        # HTTP utilities
├── vm.go          # VM operations
├── vm_vnc.go      # VNC-specific calls
├── options.go     # Client configuration options
└── interfaces/    # Interface definitions
    └── interfaces.go
```

### noVNC Integration

Using vanilla noVNC v1.6.0 served from disk

1. **Static file serving** - noVNC files served directly from disk
2. **Configurable path** - Set custom path via `novnc_path` in config
3. **Dynamic configuration** via `/mandatory.json`
4. **No patches required** for upgrades
5. **Standard compliance** with noVNC protocols

### WebSocket Proxy Implementation

The proxy maintains two WebSocket connections:

```
Client WebSocket          Proxy            Proxmox WebSocket
      │                    │                      │
      ├──RFB Protocol─────▶│                      │
      │                    ├──RFB Protocol───────▶│
      │                    │◀──RFB Protocol───────┤
      ◀──RFB Protocol──────┤                      │
```

Features:
- Zero-copy message relay
- Automatic ping/pong handling
- Connection state monitoring
- Graceful shutdown on disconnect

### Memory Management

Token storage:
- Map-based storage: O(1) lookup
- Automatic expiration via goroutines
- No persistence between restarts

Session management:
- Process isolation per session
- Automatic garbage collection
- Port recycling on cleanup

### Performance Optimizations

- **Connection Pooling**: Reuse HTTP clients
- **Lazy Loading**: Components created on-demand
- **Efficient Routing**: Path-based not regex
- **Minimal Copying**: Direct WebSocket relay

## Development

This project was almost entirely written by [Claude Code](https://claude.ai/code), Anthropic's AI coding assistant, in collaboration with a human developer. The clean architecture, comprehensive documentation, and production-ready features demonstrate the capabilities of AI-assisted development.

The general idea of implementation and some initial code patterns were inspired by and adapted from the [Proxmox-TUI](https://github.com/Noriben/Proxmox-TUI) project.

## License

This project includes:
- **noVNC v1.6.0** - Licensed under MPL 2.0 (unmodified)

## Acknowledgments

- [Claude Code](https://claude.ai/code) - AI coding assistant that wrote the majority of this codebase
- [Proxmox-TUI](https://github.com/Noriben/Proxmox-TUI) - Inspiration for the implementation approach and initial code patterns
- [noVNC](https://github.com/novnc/noVNC) - HTML5 VNC client
- [Proxmox VE](https://www.proxmox.com/) - Virtualization platform
- [Gorilla WebSocket](https://github.com/gorilla/websocket) - WebSocket library

---

**Security Notice**: This software handles sensitive credentials. Always use HTTPS in production, implement rate limiting, and follow security best practices.
