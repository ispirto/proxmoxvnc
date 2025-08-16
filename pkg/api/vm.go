package api

import (
	"fmt"
)

const (
	VMTypeQemu = "qemu"
	VMTypeLXC  = "lxc"
)

// VM represents a virtual machine or container
type VM struct {
	ID          int    `json:"vmid"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Status      string `json:"status"`
	Node        string `json:"node"`
}


// GetVmInfo retrieves information about a specific VM
func (c *Client) GetVmInfo(node, vmType string, vmid int) (*VM, error) {
	c.logger.Info("Fetching info for %s %d on node %s", vmType, vmid, node)
	
	// Build the path based on VM type
	path := fmt.Sprintf("/nodes/%s/%s/%d/status/current", node, vmType, vmid)
	
	var res map[string]interface{}
	if err := c.Get(path, &res); err != nil {
		c.logger.Error("Failed to fetch VM info: %v", err)
		return nil, fmt.Errorf("failed to fetch VM info: %w", err)
	}
	
	data, ok := res["data"].(map[string]interface{})
	if !ok {
		c.logger.Error("Unexpected VM info response format")
		return nil, fmt.Errorf("unexpected response format")
	}
	
	vm := &VM{
		ID:   vmid,
		Node: node,
		Type: vmType,
	}
	
	// Parse VM fields
	if name, ok := data["name"].(string); ok {
		vm.Name = name
	}
	if status, ok := data["status"].(string); ok {
		vm.Status = status
	}
	
	c.logger.Info("Retrieved info for VM %s (status: %s)", vm.Name, vm.Status)
	return vm, nil
}

