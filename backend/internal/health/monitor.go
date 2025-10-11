package health

import (
	"context"
	"fmt"
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

	mu sync.Mutex
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
		store:        st,
		infra:        infraCtl,
		orch:         orch,
		nodeID:       nodeID,
		interval:     interval,
		dialTimeout:  dialTimeout,
		failures:     failureThreshold,
		failureDecay: failureDecay,
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
			edgesUpdated := m.evaluateEdges(ctx)
			nsUpdated := m.evaluateNameServers(ctx)
			if edgesUpdated {
				m.rebalanceAssignments()
				m.orch.Trigger(context.Background())
			} else if nsUpdated {
				// nothing else to do; data is persisted for passive consumers
			}
		}
	}
}

func (m *Monitor) evaluateEdges(ctx context.Context) bool {
	edges, err := m.infra.EdgeIPs()
	if err != nil {
		return false
	}
	statusMap, err := m.store.GetEdgeHealthMap()
	if err != nil {
		return false
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
		next := m.checkEdge(ctx, edge, prev, now)
		if changed(prev, next) {
			if err := m.store.UpsertEdgeHealth(next); err == nil {
				updated = true
			}
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

	return updated
}

func (m *Monitor) checkEdge(ctx context.Context, ip string, prev models.EdgeHealthStatus, now time.Time) models.EdgeHealthStatus {
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
	next.Version.Counter++
	next.Version.NodeID = m.nodeID
	next.Version.Updated = now.Unix()
	if healthy {
		next.Healthy = true
		// decay failure count gradually
		if prev.Healthy {
			next.FailureCount = 0
		} else {
			// allow gradual recovery
			if now.Sub(prev.LastChecked) > m.failureDecay {
				next.FailureCount = 0
			} else if prev.FailureCount > 0 {
				next.FailureCount = prev.FailureCount - 1
			} else {
				next.FailureCount = 0
			}
		}
		next.Message = ""
	} else {
		next.Message = message
		if prev.FailureCount < m.failures {
			next.FailureCount = prev.FailureCount + 1
		}
		if next.FailureCount >= m.failures {
			next.Healthy = false
		}
	}
	return next
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

func changed(a, b models.EdgeHealthStatus) bool {
	if a.IP == "" {
		return true
	}
	if a.Healthy != b.Healthy {
		return true
	}
	if a.FailureCount != b.FailureCount {
		return true
	}
	if a.Message != b.Message {
		return true
	}
	if a.Version != b.Version {
		return true
	}
	return false
}
