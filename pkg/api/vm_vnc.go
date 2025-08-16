package api

import (
	"fmt"
)

// VNCProxyResponse represents the response from a VNC proxy request
type VNCProxyResponse struct {
	Ticket   string `json:"ticket"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Cert     string `json:"cert"`
	Password string `json:"password,omitempty"` // One-time password for WebSocket
}


// GetVNCProxyWithWebSocket creates a VNC proxy with WebSocket support and one-time password
func (c *Client) GetVNCProxyWithWebSocket(vm *VM) (*VNCProxyResponse, error) {
	c.logger.Info("Creating VNC proxy with WebSocket for VM: %s (ID: %d, Type: %s, Node: %s)", 
		vm.Name, vm.ID, vm.Type, vm.Node)
	
	if vm.Type != VMTypeQemu && vm.Type != VMTypeLXC {
		c.logger.Error("VNC proxy with WebSocket not supported for VM type: %s", vm.Type)
		return nil, fmt.Errorf("VNC proxy only available for QEMU VMs and LXC containers")
	}
	
	var res map[string]interface{}
	path := fmt.Sprintf("/nodes/%s/%s/%d/vncproxy", vm.Node, vm.Type, vm.ID)
	
	// Different parameters based on VM type
	var data map[string]interface{}
	if vm.Type == VMTypeLXC {
		// LXC containers only support websocket parameter
		data = map[string]interface{}{
			"websocket": 1,
		}
		c.logger.Debug("Using LXC-compatible parameters for VM %s (no generate-password)", vm.Name)
	} else {
		// QEMU VMs support both websocket and generate-password
		data = map[string]interface{}{
			"websocket":         1,
			"generate-password": 1,
		}
		c.logger.Debug("Using QEMU parameters for VM %s (with generate-password)", vm.Name)
	}
	
	if err := c.PostWithResponse(path, data, &res); err != nil {
		c.logger.Error("Failed to create VNC proxy with WebSocket for VM %s: %v", vm.Name, err)
		return nil, fmt.Errorf("failed to create VNC proxy with WebSocket: %w", err)
	}
	
	responseData, ok := res["data"].(map[string]interface{})
	if !ok {
		c.logger.Error("Unexpected VNC proxy WebSocket response format for VM %s", vm.Name)
		return nil, fmt.Errorf("unexpected VNC proxy response format")
	}
	
	response := &VNCProxyResponse{}
	
	if ticket, ok := responseData["ticket"].(string); ok {
		response.Ticket = ticket
	}
	
	if port, ok := responseData["port"].(string); ok {
		response.Port = port
	} else if portFloat, ok := responseData["port"].(float64); ok {
		response.Port = fmt.Sprintf("%.0f", portFloat)
	}
	
	if user, ok := responseData["user"].(string); ok {
		response.User = user
	}
	
	if cert, ok := responseData["cert"].(string); ok {
		response.Cert = cert
	}
	
	// Password is only available for QEMU VMs with generate-password=1
	if password, ok := responseData["password"].(string); ok {
		response.Password = password
		c.logger.Debug("VNC proxy one-time password obtained for VM %s", vm.Name)
	} else if vm.Type == VMTypeLXC {
		c.logger.Debug("No one-time password for LXC container %s (expected)", vm.Name)
	}
	
	c.logger.Info("VNC proxy with WebSocket created successfully for VM %s - Port: %s, Has Password: %t",
		vm.Name, response.Port, response.Password != "")
	
	return response, nil
}