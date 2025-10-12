package health

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"aki-cloud/backend/internal/infra"
	"aki-cloud/backend/internal/models"
	"aki-cloud/backend/internal/orchestrator"
	"aki-cloud/backend/internal/store"

	"github.com/miekg/dns"
)

// Monitor runs reachability checks against edge IPs.
type Monitor struct {
	store        *store.Store
	infra        *infra.Controller
	orch         *orchestrator.Service
	nodeID       string
	interval     time.Duration
	dialTimeout  time.Duration
	failures     int
	failureDecay time.Duration

	mu             sync.Mutex
	lastRebalance  time.Time
	reconcileEvery time.Duration
}

// New creates a new edge health monitor.
func New(st *store.Store, infraCtl *infra.Controller, orch *orchestrator.Service, nodeID string, interval time.Duration, dialTimeout time.Duration, failureThreshold int, failureDecay time.Duration) *Monitor {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if dialTimeout <= 0 {
		dialTimeout = 3 * time.Second
	}
	if failureThreshold <= 0 {
		failureThreshold = 3
	}
	if failureDecay <= 0 {
		failureDecay = 5 * time.Minute
	}
	return &Monitor{
		store:          st,
		infra:          infraCtl,
		orch:           orch,
		nodeID:         nodeID,
		interval:       interval,
		dialTimeout:    dialTimeout,
		failures:       failureThreshold,
		failureDecay:   failureDecay,
		reconcileEvery: interval * 2,
	}
}

// Start begins the monitoring loop until ctx is cancelled.
func (m *Monitor) Start(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			edgeHealth, edgesUpdated := m.evaluateEdges(ctx)
			nsUpdated := m.evaluateNameServers(ctx)
			pruned := m.pruneDormantNodes(edgeHealth)
			rebalance := edgesUpdated
			if pruned {
				rebalance = true
			}
			if !rebalance && m.reconcileEvery > 0 {
				m.mu.Lock()
				if time.Since(m.lastRebalance) >= m.reconcileEvery {
					rebalance = true
				}
				m.mu.Unlock()
			}
			if rebalance {
				now := time.Now().UTC()
				mutated := m.rebalanceAssignments()
				m.mu.Lock()
				m.lastRebalance = now
				m.mu.Unlock()
				if mutated {
					if m.orch != nil {
						m.orch.Trigger(context.Background())
					}
				} else if edgesUpdated && m.orch != nil {
					m.orch.Trigger(context.Background())
				}
			} else if nsUpdated || pruned {
				// nothing else to do; data is persisted for passive consumers
			}
		}
	}
}

func (m *Monitor) evaluateEdges(ctx context.Context) (map[string]models.EdgeHealthStatus, bool) {
	edges, err := m.infra.EdgeIPs()
	if err != nil {
		return nil, false
	}
	statusMap, err := m.store.GetEdgeHealthMap()
	if err != nil {
		return nil, false
	}

	updated := false
	now := time.Now().UTC()
	seen := make(map[string]struct{}, len(edges))
	for _, edge := range edges {
		edge = strings.TrimSpace(edge)
		if edge == "" {
			continue
		}
		seen[edge] = struct{}{}
		prev := statusMap[edge]
		next, stateChanged := m.checkEdge(ctx, edge, prev, now)
		if err := m.store.UpsertEdgeHealth(next); err == nil && stateChanged {
			updated = true
		}
	}

	// Clean up statuses for edges no longer present.
	for ip := range statusMap {
		if _, ok := seen[ip]; ok {
			continue
		}
		if err := m.store.DeleteEdgeHealth(ip); err == nil {
			updated = true
		}
	}

	return statusMap, updated
}

func (m *Monitor) checkEdge(ctx context.Context, ip string, prev models.EdgeHealthStatus, now time.Time) (models.EdgeHealthStatus, bool) {
	address := net.JoinHostPort(ip, "80")
	dialCtx, cancel := context.WithTimeout(ctx, m.dialTimeout)
	defer cancel()

	conn, err := (&net.Dialer{Timeout: m.dialTimeout}).DialContext(dialCtx, "tcp", address)
	healthy := err == nil
	if conn != nil {
		_ = conn.Close()
	}

	message := ""
	if err != nil {
		message = err.Error()
	}

	next := prev
	next.IP = ip
	next.LastChecked = now
	stateChanged := prev.IP == ""
	if healthy {
		if !prev.Healthy {
			stateChanged = true
		}
		next.Healthy = true
		var desiredFailures int
		if prev.Healthy {
			desiredFailures = 0
		} else if now.Sub(prev.LastChecked) > m.failureDecay {
			desiredFailures = 0
		} else if prev.FailureCount > 0 {
			desiredFailures = prev.FailureCount - 1
		} else {
			desiredFailures = 0
		}
		if next.FailureCount != desiredFailures {
			next.FailureCount = desiredFailures
			stateChanged = true
		}
		if next.Message != "" {
			next.Message = ""
			stateChanged = true
		}
	} else {
		if prev.Healthy {
			stateChanged = true
		}
		next.Healthy = prev.Healthy
		failures := prev.FailureCount
		if failures < m.failures {
			failures++
		}
		if failures >= m.failures && next.Healthy {
			next.Healthy = false
			stateChanged = true
		}
		if next.FailureCount != failures {
			next.FailureCount = failures
			stateChanged = true
		}
		if next.Message != message {
			next.Message = message
			stateChanged = true
		}
	}

	if stateChanged {
		next.Version.Counter++
		if next.Version.Counter <= 0 {
			next.Version.Counter = 1
		}
		next.Version.NodeID = m.nodeID
		next.Version.Updated = now.Unix()
	}

	return next, stateChanged
}

func (m *Monitor) evaluateNameServers(ctx context.Context) bool {
	nsList, err := m.infra.ActiveNameServers()
	if err != nil {
		return false
	}
	if len(nsList) == 0 {
		return false
	}
	statuses := make([]models.NameServerHealth, 0, len(nsList))
	for _, ns := range nsList {
		statuses = append(statuses, m.checkNameServer(ctx, ns))
	}
	if err := m.store.SaveNameServerStatus(statuses); err != nil {
		log.Printf("health: persist nameserver status failed: %v", err)
		return false
	}
	return true
}

func (m *Monitor) rebalanceAssignments() bool {
	domains, err := m.store.GetDomains()
	if err != nil {
		log.Printf("health: fetch domains for reassignment failed: %v", err)
		return false
	}
	endpoints, err := m.infra.EdgeEndpoints()
	if err != nil {
		log.Printf("health: fetch edge endpoints for reassignment failed: %v", err)
		return false
	}
	health, err := m.store.GetEdgeHealthMap()
	if err != nil {
		log.Printf("health: fetch edge health for reassignment failed: %v", err)
		return false
	}
	mutated := false
	for _, domain := range domains {
		if !domain.Proxied {
			continue
		}
		rec := domain
		changed, err := infra.EnsureDomainEdgeAssignment(&rec, endpoints, health)
		if err != nil {
			if _, ok := err.(models.ErrValidation); ok {
				continue
			}
			log.Printf("health: reassignment for %s failed: %v", rec.Domain, err)
			continue
		}
		if !changed {
			continue
		}
		now := time.Now().UTC()
		rec.UpdatedAt = now
		rec.Version.Counter++
		rec.Version.NodeID = m.nodeID
		rec.Version.Updated = now.Unix()
		if err := m.store.UpsertDomain(rec); err != nil {
			log.Printf("health: persist reassignment for %s failed: %v", rec.Domain, err)
			continue
		}
		mutated = true
	}
	return mutated
}

func (m *Monitor) pruneDormantNodes(health map[string]models.EdgeHealthStatus) bool {
	if health == nil {
		var err error
		health, err = m.store.GetEdgeHealthMap()
		if err != nil {
			log.Printf("health: fetch edge health for pruning failed: %v", err)
			return false
		}
	}
	nodes, err := m.store.GetNodesIncludingDeleted()
	if err != nil {
		log.Printf("health: load nodes for pruning failed: %v", err)
		return false
	}
	now := time.Now().UTC()
	changed := false

	// Deduplicate nodes with identical names, keeping the freshest entry.
	// Also check for duplicate IPs to prevent conflicts
	type nodeRef struct {
		node models.Node
	}
	byName := make(map[string]nodeRef, len(nodes))
	byIP := make(map[string]models.Node, len(nodes)*2)
	var duplicates []models.Node
	
	for _, node := range nodes {
		if node.IsDeleted() {
			continue
		}
		
		// Check for duplicate names
		nameKey := strings.ToLower(strings.TrimSpace(node.Name))
		if existing, ok := byName[nameKey]; ok {
			// Found duplicate name - keep the better one
			if preferNode(node, existing.node) {
				log.Printf("health: found duplicate node %s (keeping %s, removing %s)", 
					nameKey, node.ID, existing.node.ID)
				duplicates = append(duplicates, existing.node)
				byName[nameKey] = nodeRef{node: node}
			} else {
				log.Printf("health: found duplicate node %s (keeping %s, removing %s)", 
					nameKey, existing.node.ID, node.ID)
				duplicates = append(duplicates, node)
			}
		} else {
			byName[nameKey] = nodeRef{node: node}
		}
		
		// Check for duplicate IPs (edge nodes sharing same IPs is problematic)
		for _, ip := range node.EdgeIPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			if existing, ok := byIP[ip]; ok && existing.ID != node.ID {
				// Two nodes claiming the same edge IP - keep the newer/better one
				if preferNode(node, existing) {
					log.Printf("health: IP conflict on %s between %s and %s (keeping %s)",
						ip, node.Name, existing.Name, node.Name)
					if !contains(duplicates, existing) {
						duplicates = append(duplicates, existing)
					}
				} else {
					log.Printf("health: IP conflict on %s between %s and %s (keeping %s)",
						ip, node.Name, existing.Name, existing.Name)
					if !contains(duplicates, node) {
						duplicates = append(duplicates, node)
					}
				}
			} else {
				byIP[ip] = node
			}
		}
	}
	for _, dup := range duplicates {
		if err := m.store.MarkNodeDeleted(dup.ID, m.nodeID, now); err != nil {
			log.Printf("health: mark duplicate node %s deleted failed: %v", dup.ID, err)
			continue
		}
		log.Printf("health: removed duplicate node definition %s (%s)", dup.Name, dup.ID)
		changed = true
	}

	// Re-load active nodes to reflect any deletions.
	activeNodes, err := m.store.GetNodes()
	if err != nil {
		log.Printf("health: reload nodes after duplication pruning failed: %v", err)
		return changed
	}

	for _, node := range activeNodes {
		if node.ID == m.nodeID {
			continue
		}
		if len(node.EdgeIPs) == 0 {
			continue
		}
		if node.EdgeManual {
			continue
		}
		allStale := true
		tracked := 0
		for _, ip := range node.EdgeIPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			status, ok := health[ip]
			if !ok || status.LastChecked.IsZero() {
				allStale = false
				continue
			}
			tracked++
			if status.Healthy {
				allStale = false
				break
			}
			if status.FailureCount < m.failures {
				allStale = false
				break
			}
		}
		if !allStale || tracked == 0 {
			continue
		}
		originalIPs := append([]string{}, node.EdgeIPs...)
		node.EdgeManual = true
		node.EdgeIPs = nil
		node.ComputeEdgeIPs()
		node.UpdatedAt = now
		node.Version.Counter++
		if node.Version.Counter <= 0 {
			node.Version.Counter = 1
		}
		node.Version.NodeID = m.nodeID
		node.Version.Updated = now.Unix()
		if err := m.store.UpsertNode(node); err != nil {
			log.Printf("health: disable edges for %s failed: %v", node.Name, err)
			continue
		}
		log.Printf("health: disabled edge assignments for node %s (%s) after sustained failures", node.Name, node.ID)
		if node.ID == m.nodeID {
			if err := m.store.SaveLocalNodeSnapshot(node); err != nil {
				log.Printf("health: update local node snapshot failed: %v", err)
			}
		}
		for _, ip := range originalIPs {
			if err := m.store.DeleteEdgeHealth(ip); err != nil && !errors.Is(err, fs.ErrNotExist) {
				log.Printf("health: prune edge health %s failed: %v", ip, err)
			}
		}
		changed = true
	}
	if changed {
		if nodesRefreshed, err := m.store.GetNodes(); err == nil {
			if err := m.store.PruneEdgeHealthByNodes(nodesRefreshed); err != nil {
				log.Printf("health: prune edge health after node disable failed: %v", err)
			}
		} else {
			log.Printf("health: prune edge health after node disable failed: %v", err)
		}
	}
	return changed
}

func preferNode(a, b models.Node) bool {
	// Prefer non-deleted over deleted
	if a.IsDeleted() != b.IsDeleted() {
		return !a.IsDeleted()
	}
	// Prefer higher version counter (more recent updates)
	if a.Version.Counter != b.Version.Counter {
		return a.Version.Counter > b.Version.Counter
	}
	// Prefer more recently updated
	if !a.UpdatedAt.Equal(b.UpdatedAt) {
		return a.UpdatedAt.After(b.UpdatedAt)
	}
	// Tie-breaker: use ID comparison for deterministic choice
	return strings.Compare(a.ID, b.ID) > 0
}

func contains(nodes []models.Node, target models.Node) bool {
	for _, n := range nodes {
		if n.ID == target.ID {
			return true
		}
	}
	return false
}

func (m *Monitor) checkNameServer(ctx context.Context, ns infra.NameServer) models.NameServerHealth {
	result := models.NameServerHealth{
		NodeID: ns.NodeID,
		FQDN:   ns.FQDN,
		IPv4:   ns.IPv4,
	}
	base := strings.TrimSpace(ns.BaseZone)
	if base == "" {
		base = ns.FQDN
	}
	fqdn := dns.Fqdn(base)
	client := &dns.Client{
		Timeout: m.dialTimeout,
	}
	msg := dns.Msg{}
	msg.SetQuestion(fqdn, dns.TypeNS)
	start := time.Now()
	resp, _, err := client.ExchangeContext(ctx, &msg, net.JoinHostPort(ns.IPv4, "53"))
	latency := time.Since(start)
	result.CheckedAt = time.Now().UTC()
	result.LatencyMS = latency.Milliseconds()
	if err != nil {
		result.Healthy = false
		result.Message = err.Error()
		return result
	}
	if resp == nil {
		result.Healthy = false
		result.Message = "nil response"
		return result
	}
	if resp.Rcode != dns.RcodeSuccess {
		if text, ok := dns.RcodeToString[resp.Rcode]; ok {
			result.Message = text
		} else {
			result.Message = fmt.Sprintf("rcode %d", resp.Rcode)
		}
		result.Healthy = false
		return result
	}
	if len(resp.Answer) == 0 {
		result.Healthy = false
		result.Message = "empty answer"
		return result
	}
	result.Healthy = true
	return result
}
