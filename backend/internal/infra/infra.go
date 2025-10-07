package infra

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aki-cloud/backend/internal/store"
)

// Controller provides infra views computed from persisted data.
type Controller struct {
	store   *store.Store
	dataDir string
}

// New creates a new infra controller.
func New(st *store.Store, dataDir string) *Controller {
	return &Controller{store: st, dataDir: dataDir}
}

// NameServer represents a computed NS record.
type NameServer struct {
	NodeID   string `json:"node_id"`
	Name     string `json:"name"`
	FQDN     string `json:"fqdn"`
	IPv4     string `json:"ipv4"`
	NSLabel  string `json:"ns_label"`
	BaseZone string `json:"base_zone"`
}

// ActiveNameServers returns the current NS set based on node definitions.
func (c *Controller) ActiveNameServers() ([]NameServer, error) {
	nodes, err := c.store.GetNodes()
	if err != nil {
		return nil, err
	}
	var out []NameServer
	for _, node := range nodes {
		label := node.NSLabel
		base := node.NSBase
		if label == "" || base == "" {
			label, base = c.localNSMetadata()
		}
		for _, ip := range node.NSIPs {
			ns := NameServer{
				NodeID:   node.ID,
				Name:     node.Name,
				FQDN:     fmt.Sprintf("%s.%s.%s", sanitizeLabel(node.Name), label, base),
				IPv4:     ip,
				NSLabel:  label,
				BaseZone: base,
			}
			out = append(out, ns)
		}
	}
	return out, nil
}

func sanitizeLabel(in string) string {
	return strings.ToLower(strings.ReplaceAll(in, "_", "-"))
}

// EdgeIPs returns list of non-NS IPs across the cluster.
func (c *Controller) EdgeIPs() ([]string, error) {
	nodes, err := c.store.GetNodes()
	if err != nil {
		return nil, err
	}
	var edges []string
	for _, node := range nodes {
		node.ComputeEdgeIPs()
		edges = append(edges, node.EdgeIPs...)
	}
	return edges, nil
}

type localNode struct {
	NSLabel string `json:"ns_label"`
	NSBase  string `json:"ns_base_domain"`
}

func (c *Controller) localNSMetadata() (label string, base string) {
	path := filepath.Join(c.dataDir, "cluster", "node.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return "dns", "local.invalid"
	}
	var node localNode
	if err := json.Unmarshal(data, &node); err != nil {
		return "dns", "local.invalid"
	}
	if node.NSLabel == "" {
		node.NSLabel = "dns"
	}
	if node.NSBase == "" {
		node.NSBase = "local.invalid"
	}
	return node.NSLabel, node.NSBase
}
