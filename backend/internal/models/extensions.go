package models

import "time"

// ExtensionScope indicates whether an extension applies globally, per-domain, or per-node.
type ExtensionScope string

const (
	// ExtensionScopeGlobal applies cluster-wide.
	ExtensionScopeGlobal ExtensionScope = "global"
	// ExtensionScopeDomain applies to individual domains.
	ExtensionScopeDomain ExtensionScope = "domain"
	// ExtensionScopeNode applies to specific nodes.
	ExtensionScopeNode ExtensionScope = "node"
)

// ExtensionKeys used throughout the system.
const (
	ExtensionEdgeCache         = "edge_cache"
	ExtensionRandomServerNames = "random_server_headers"
	ExtensionPlaceholderPages  = "placeholder_pages"
	ExtensionVanityNameServers = "vanity_nameservers"
	ExtensionSearchBotLogs     = "searchbot_logs"
)

// ExtensionState persists runtime configuration for an extension.
type ExtensionState struct {
	Enabled   bool                   `json:"enabled"`
	Config    map[string]interface{} `json:"config,omitempty"`
	UpdatedAt time.Time              `json:"updated_at,omitempty"`
	UpdatedBy string                 `json:"updated_by,omitempty"`
}

// ExtensionsConfig captures cluster-wide extension state.
type ExtensionsConfig struct {
	Global map[string]ExtensionState            `json:"global,omitempty"`
	Domain map[string]map[string]ExtensionState `json:"domain,omitempty"`
	Node   map[string]map[string]ExtensionState `json:"node,omitempty"`
}

// Clone makes a shallow copy safe for mutation.
func (cfg ExtensionsConfig) Clone() ExtensionsConfig {
	out := ExtensionsConfig{
		Global: make(map[string]ExtensionState, len(cfg.Global)),
	}
	for k, v := range cfg.Global {
		state := v
		if v.Config != nil {
			state.Config = make(map[string]interface{}, len(v.Config))
			for ck, cv := range v.Config {
				state.Config[ck] = cv
			}
		}
		out.Global[k] = state
	}
	if len(cfg.Domain) > 0 {
		out.Domain = make(map[string]map[string]ExtensionState, len(cfg.Domain))
		for domain, extMap := range cfg.Domain {
			next := make(map[string]ExtensionState, len(extMap))
			for key, state := range extMap {
				copyState := state
				if state.Config != nil {
					copyState.Config = make(map[string]interface{}, len(state.Config))
					for ck, cv := range state.Config {
						copyState.Config[ck] = cv
					}
				}
				next[key] = copyState
			}
			out.Domain[domain] = next
		}
	}
	if len(cfg.Node) > 0 {
		out.Node = make(map[string]map[string]ExtensionState, len(cfg.Node))
		for nodeID, extMap := range cfg.Node {
			next := make(map[string]ExtensionState, len(extMap))
			for key, state := range extMap {
				copyState := state
				if state.Config != nil {
					copyState.Config = make(map[string]interface{}, len(state.Config))
					for ck, cv := range state.Config {
						copyState.Config[ck] = cv
					}
				}
				next[key] = copyState
			}
			out.Node[nodeID] = next
		}
	}
	return out
}
