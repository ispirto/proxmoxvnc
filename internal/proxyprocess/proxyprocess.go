package proxyprocess

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ispirto/proxmoxvnc/internal/config"
	"github.com/ispirto/proxmoxvnc/internal/logger"
	"github.com/ispirto/proxmoxvnc/internal/vnc"
	"github.com/ispirto/proxmoxvnc/pkg/api"
)

// ProxyProcess manages the lifecycle of a VNC proxy connection to a VM
type ProxyProcess struct {
	proxmoxConfig *config.ProxmoxConfig
	routerConfig  *config.Config
	logger        *logger.Logger
	client        *api.Client
	service       *vnc.Service
	onConnect     func()  // Callback when client connects
	onDisconnect  func()  // Callback when client disconnects
}

// ProxyResult contains the VNC session details returned after successful proxy setup
type ProxyResult struct {
	URL       string `json:"url"`
	SessionID string `json:"session_id"`
	Port      int    `json:"port"`
}

// NewProxyProcessWithConfig creates a new proxy process with the given Proxmox and router configurations
func NewProxyProcessWithConfig(proxmoxCfg *config.ProxmoxConfig, routerCfg *config.Config) (*ProxyProcess, error) {
	// Use global logger settings with PROXY component name
	processLogger := logger.CreateComponentLogger("PROXY")
	
	return &ProxyProcess{
		proxmoxConfig: proxmoxCfg,
		routerConfig:  routerCfg,
		logger:        processLogger,
	}, nil
}

// SetOnConnect sets the callback for when a client connects
func (pp *ProxyProcess) SetOnConnect(callback func()) {
	pp.onConnect = callback
}

// SetOnDisconnect sets the callback for when a client disconnects
func (pp *ProxyProcess) SetOnDisconnect(callback func()) {
	pp.onDisconnect = callback
}

// StartVMProxy initiates a VNC proxy connection to the specified VM
// It verifies the VM exists and is running, then creates a VNC session
func (pp *ProxyProcess) StartVMProxy(vmID int) (*ProxyResult, error) {
	// Use the node name from Proxmox config
	nodeName := pp.proxmoxConfig.GetNodeName()
	
	// Create a separate logger for API client
	apiLogger := logger.CreateComponentLogger("API")
	apiClient, err := api.NewClient(pp.proxmoxConfig, api.WithLogger(apiLogger))
	if err != nil {
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}
	
	pp.client = apiClient
	
	// Try to get VM info as QEMU first, then LXC
	var vm *api.VM
	var vmType string
	
	qemuVM, qemuErr := apiClient.GetVmInfo(nodeName, "qemu", vmID)
	if qemuErr == nil {
		vm = qemuVM
		vmType = "qemu"
		pp.logger.Info("Found QEMU VM: %s (ID: %d)", vm.Name, vm.ID)
	} else {
		lxcVM, lxcErr := apiClient.GetVmInfo(nodeName, "lxc", vmID)
		if lxcErr == nil {
			vm = lxcVM
			vmType = "lxc"
			pp.logger.Info("Found LXC container: %s (ID: %d)", vm.Name, vm.ID)
		} else {
			return nil, fmt.Errorf("VM/Container %d does not exist on node %s", vmID, nodeName)
		}
	}
	
	vm.Type = vmType
	
	if vm.Status != "running" {
		return nil, fmt.Errorf("%s %d (%s) is not running (status: %s)", 
			strings.ToUpper(vmType), vmID, vm.Name, vm.Status)
	}
	
	// Create a separate logger for VNC service
	vncLogger := logger.CreateComponentLogger("VNC-SERVICE")
	pp.service = vnc.NewService(apiClient, vncLogger)
	
	if publicIP := pp.routerConfig.GetPublicIP(); publicIP != "" {
		pp.service.SetPublicIP(publicIP)
	}
	
	// Set custom noVNC path if configured
	if pp.routerConfig.NoVNCPath != "" {
		pp.service.SetNoVNCPath(pp.routerConfig.NoVNCPath)
	}
	
	vncURL, session, err := pp.service.ConnectToVMEmbedded(vm)
	if err != nil {
		return nil, fmt.Errorf("failed to create VNC session: %w", err)
	}
	
	// Set up a custom notifier wrapper to trigger our callbacks
	if pp.onConnect != nil || pp.onDisconnect != nil {
		pp.wrapSessionWithCallbacks(session)
	}
	
	pp.logger.Info("VNC proxy started for VM %d on node %s: %s", vmID, nodeName, vncURL)
	
	go pp.monitorDisconnection(session)
	
	return &ProxyResult{
		URL:       vncURL,
		SessionID: session.ID,
		Port:      session.Port,
	}, nil
}

// wrapSessionWithCallbacks sets up monitoring for session state changes
func (pp *ProxyProcess) wrapSessionWithCallbacks(session *vnc.VNCSession) {
	// Monitor the session state to detect connections
	// We can't directly override the session methods, so we poll the state
	go pp.monitorSessionState(session)
}

// monitorSessionState polls the session to detect client connections
func (pp *ProxyProcess) monitorSessionState(session *vnc.VNCSession) {
	hasConnected := false
	checkInterval := 100 * time.Millisecond
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			connections := session.GetConnectionCount()
			
			// Check for first connection
			if !hasConnected && connections > 0 {
				hasConnected = true
				if pp.onConnect != nil {
					pp.logger.Info("Client connected, triggering callback")
					pp.onConnect()
				}
			}
			
			// Check if session is shutting down (connections == 0 after having connected)
			if hasConnected && connections == 0 {
				return  // Session has ended
			}
		}
	}
}

// monitorDisconnection waits for client disconnection and performs cleanup
func (pp *ProxyProcess) monitorDisconnection(session *vnc.VNCSession) {
	ctx := context.Background()
	disconnected := session.WaitForDisconnect(ctx)
	
	if disconnected {
		pp.logger.Info("Client disconnected from session %s, cleaning up", session.ID)
		
		// Trigger disconnect callback
		if pp.onDisconnect != nil {
			pp.onDisconnect()
		}
		
		time.Sleep(2 * time.Second)
		
		if err := session.Shutdown(); err != nil {
			pp.logger.Error("Error shutting down session: %v", err)
		}
		
		if pp.service != nil {
			pp.service.CloseAllSessions()
		}
		
		pp.logger.Info("Proxy process exiting for session %s", session.ID)
	}
}


// ParseVMID converts a string VM ID to an integer with validation
func ParseVMID(vmidStr string) (int, error) {
	vmid, err := strconv.Atoi(vmidStr)
	if err != nil {
		return 0, fmt.Errorf("invalid VM ID: %s", vmidStr)
	}
	if vmid <= 0 {
		return 0, fmt.Errorf("VM ID must be positive: %d", vmid)
	}
	return vmid, nil
}
