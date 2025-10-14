package render

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	htmltmpl "html/template"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"aki-cloud/backend/internal/extensions"
	"aki-cloud/backend/internal/infra"
	"aki-cloud/backend/internal/models"
	"aki-cloud/backend/internal/store"
)

// CoreDNSGenerator renders CoreDNS configuration using templates.
type CoreDNSGenerator struct {
	Store        *store.Store
	Infra        *infra.Controller
	DataDir      string
	Template     string
	NSLabel      string
	NSBaseDomain string
}

// OpenRestyGenerator renders OpenResty configs.
type OpenRestyGenerator struct {
	Store        *store.Store
	Infra        *infra.Controller
	Extensions   *extensions.Service
	DataDir      string
	NginxTmpl    string
	SitesTmpl    string
	OutputDir    string
	NSLabel      string
	NSBaseDomain string
}

// ZoneFile represents a DNS zone rendering payload.
type ZoneFile struct {
	Domain     string
	TTL        int
	PrimaryNS  string
	AdminEmail string
	Serial     string
	NSRecords  []string
	ARecords   []string
	Extra      []ZoneRecord
}

// ZoneRecord represents an arbitrary record in a zone file.
type ZoneRecord struct {
	Name  string
	Type  string
	Value string
}

const (
	challengeTypeHTTP = "http-01"
	challengeTypeDNS  = "dns-01"
)

// Render writes CoreDNS Corefile and zone files to data directory.
func (g *CoreDNSGenerator) Render() error {
	domains, err := g.Store.GetDomains()
	if err != nil {
		return err
	}
	nodes, err := g.Store.GetNodes()
	if err != nil {
		return err
	}
	nodeMap := make(map[string]models.Node, len(nodes))
	for _, node := range nodes {
		nodeMap[node.ID] = node
	}
	nsList, err := g.Infra.ActiveNameServers()
	if err != nil {
		return err
	}
	local := g.localNodeInfo()
	if stored, ok := nodeMap[local.NodeID]; ok {
		if len(local.IPs) == 0 {
			local.IPs = append([]string{}, stored.IPs...)
		}
		if len(local.NSIPs) == 0 {
			local.NSIPs = append([]string{}, stored.NSIPs...)
		}
	}
	filteredNS := make([]infra.NameServer, 0, len(nsList))
	if local.NodeID != "" {
		for _, ns := range nsList {
			if ns.NodeID == local.NodeID {
				filteredNS = append(filteredNS, ns)
			}
		}
	}
	// If no NS found by NodeID, create NS from local node.json NSIPs
	if len(filteredNS) == 0 && len(local.NSIPs) > 0 {
		for _, ip := range local.NSIPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			// Create a minimal NS entry for local IP binding
			// Use NS configuration from environment variables
			nsLabel := g.NSLabel
			if nsLabel == "" {
				nsLabel = "dns" // fallback default
			}
			nsBaseDomain := g.NSBaseDomain
			if nsBaseDomain == "" {
				nsBaseDomain = "aki.cloud" // fallback default
			}
			filteredNS = append(filteredNS, infra.NameServer{
				IPv4: ip,
				FQDN: fmt.Sprintf("%s.%s.%s", local.Name, nsLabel, nsBaseDomain),
			})
		}
	}
	activeNS := filteredNS
	edges, err := g.Infra.EdgeIPs()
	if err != nil {
		return err
	}
	edgeHealth, err := g.Store.GetEdgeHealthMap()
	if err != nil {
		return err
	}
	healthyEdges := filterHealthyEdges(edges, edgeHealth)
	if len(healthyEdges) == 0 {
		healthyEdges = edges
	}

	fmt.Printf("CoreDNS generator: data dir %s, %d domain(s), %d nameserver(s), %d edge IP(s)\n", g.DataDir, len(domains), len(activeNS), len(edges))
	zonesDir := filepath.Join(g.DataDir, "dns", "zones")
	if err := os.MkdirAll(zonesDir, 0o755); err != nil {
		return err
	}
	if entries, err := os.ReadDir(zonesDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if strings.HasSuffix(entry.Name(), ".zone") {
				_ = os.Remove(filepath.Join(zonesDir, entry.Name()))
			}
		}
	}

	// build zone files
	zoneFiles := make([]ZoneFile, 0, len(domains))
	now := time.Now().UTC()
	serial := fmt.Sprintf("%d", now.Unix())
	primaryNS := "ns1.local.invalid."
	if len(activeNS) > 0 {
		primaryNS = ensureDot(activeNS[0].FQDN)
	}
	for _, domain := range domains {
		ttl := domain.TTL
		if ttl <= 0 {
			ttl = 60
		}
		ttl = jitterSeconds(ttl, 20, domain.Domain)
		if ttl <= 0 {
			ttl = 60
		}
		challengeExtras := make([]ZoneRecord, 0, len(domain.TLS.Challenges))
		expiryCutoff := now.Add(-1 * time.Minute)
		for _, ch := range domain.TLS.Challenges {
			if ch.ChallengeType != "" && ch.ChallengeType != challengeTypeDNS {
				continue
			}
			if ch.DNSName == "" || ch.DNSValue == "" {
				continue
			}
			if !ch.ExpiresAt.IsZero() && ch.ExpiresAt.Before(expiryCutoff) {
				continue
			}
			label := relativeLabel(ch.DNSName, domain.Domain)
			challengeExtras = append(challengeExtras, ZoneRecord{
				Name:  label,
				Type:  "TXT",
				Value: fmt.Sprintf(`"%s"`, ch.DNSValue),
			})
		}
		arecords := make([]string, 0, 2)
		if domain.Proxied {
			// Only use the assigned IP, never all edge IPs
			if ip := strings.TrimSpace(domain.Edge.AssignedIP); ip != "" {
				arecords = append(arecords, ip)
				fmt.Printf("DEBUG: Domain %s using assigned IP %s\n", domain.Domain, ip)
			} else {
				fmt.Printf("DEBUG: Domain %s has no assigned IP (Edge: %+v)\n", domain.Domain, domain.Edge)
			}
		} else {
			fmt.Printf("DEBUG: Domain %s is not proxied\n", domain.Domain)
		}
		// Fall back to origin IP if no edge IP assigned or not proxied
		if len(arecords) == 0 && strings.TrimSpace(domain.OriginIP) != "" {
			fmt.Printf("DEBUG: Domain %s falling back to origin IP %s\n", domain.Domain, domain.OriginIP)
			arecords = append(arecords, domain.OriginIP)
		}
		nsRecords := make([]string, 0, len(activeNS))
		for _, ns := range activeNS {
			nsRecords = append(nsRecords, ensureDot(ns.FQDN))
		}
		if len(nsRecords) == 0 {
			nsRecords = append(nsRecords, primaryNS)
		}
		zone := ZoneFile{
			Domain:     strings.TrimSuffix(domain.Domain, "."),
			TTL:        ttl,
			PrimaryNS:  primaryNS,
			AdminEmail: fmt.Sprintf("admin.%s.", strings.TrimSuffix(domain.Domain, ".")),
			Serial:     serial,
			NSRecords:  nsRecords,
			ARecords:   uniqueStrings(arecords),
			Extra:      dedupeRecords(challengeExtras),
		}
		zoneFiles = append(zoneFiles, zone)
	}

	infraZones := g.buildInfrastructureZones(activeNS, serial)
	zoneFiles = append(zoneFiles, infraZones...)

	for _, zone := range zoneFiles {
		fmt.Printf("CoreDNS generator: writing zone for %s (%d NS, %d A, %d extra)\n", zone.Domain, len(zone.NSRecords), len(zone.ARecords), len(zone.Extra))
		if err := writeZoneFile(zonesDir, zone); err != nil {
			return err
		}
	}

	// render Corefile
	bindIPs := make([]string, 0, len(filteredNS))
	for _, ns := range filteredNS {
		ip := strings.TrimSpace(ns.IPv4)
		if ip == "" {
			continue
		}
		bindIPs = append(bindIPs, ip)
	}
	bindIPs = uniqueStrings(bindIPs)
	coreTemplate, err := template.ParseFiles(g.Template)
	if err != nil {
		return err
	}
	type zoneMeta struct {
		Domain   string
		FileName string
	}
	zones := make([]zoneMeta, 0, len(zoneFiles))
	for _, z := range zoneFiles {
		zones = append(zones, zoneMeta{Domain: ensureDot(z.Domain), FileName: fmt.Sprintf("%s.zone", z.Domain)})
	}
	cacheSuccessTTL := envIntPositive("COREDNS_CACHE_SUCCESS_TTL", 900)
	cacheDenialTTL := envIntPositive("COREDNS_CACHE_DENIAL_TTL", 60)
	bufSize := envIntPositive("COREDNS_EDNS_BUFFER", 1232)
	queryLog := envBool("COREDNS_QUERY_LOG", false)
	queryLogClass := envStringOrDefault("COREDNS_QUERY_LOG_CLASS", "denial")
	data := struct {
		NameServers     []infra.NameServer
		BindIPs         []string
		Zones           []zoneMeta
		ZonesDir        string
		CacheSuccessTTL int
		CacheDenialTTL  int
		BufSize         int
		QueryLog        bool
		QueryLogClass   string
	}{
		NameServers:     filteredNS,
		BindIPs:         bindIPs,
		Zones:           zones,
		ZonesDir:        zonesDir,
		CacheSuccessTTL: cacheSuccessTTL,
		CacheDenialTTL:  cacheDenialTTL,
		BufSize:         bufSize,
		QueryLog:        queryLog,
		QueryLogClass:   queryLogClass,
	}
	buf := bytes.Buffer{}
	if err := coreTemplate.Execute(&buf, data); err != nil {
		return err
	}
	corefilePath := filepath.Join(g.DataDir, "dns", "Corefile")
	if err := os.MkdirAll(filepath.Dir(corefilePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(corefilePath, buf.Bytes(), 0o644)
}

func writeZoneFile(dir string, zone ZoneFile) error {
	tmpl := `$ORIGIN {{.Domain}}.
$TTL {{.TTL}}
@ IN SOA {{.PrimaryNS}} {{.AdminEmail}} {{.Serial}} 3600 600 86400 60
{{- range .NSRecords}}
@ IN NS {{.}}
{{- end}}
{{- range .ARecords}}
@ IN A {{.}}
{{- end}}
{{- range .Extra}}
{{.Name}} IN {{.Type}} {{.Value}}
{{- end}}
`
	parsed, err := template.New("zone").Parse(tmpl)
	if err != nil {
		return err
	}
	buf := bytes.Buffer{}
	if err := parsed.Execute(&buf, zone); err != nil {
		return err
	}
	file := filepath.Join(dir, fmt.Sprintf("%s.zone", zone.Domain))
	return os.WriteFile(file, buf.Bytes(), 0o644)
}

func (g *CoreDNSGenerator) buildInfrastructureZones(nsList []infra.NameServer, serial string) []ZoneFile {
	if len(nsList) == 0 {
		return nil
	}
	grouped := make(map[string][]infra.NameServer)
	for _, ns := range nsList {
		base := strings.TrimSuffix(ns.BaseZone, ".")
		if base == "" {
			continue
		}
		grouped[base] = append(grouped[base], ns)
	}

	zones := make([]ZoneFile, 0, len(grouped))
	for base, servers := range grouped {
		if len(servers) == 0 {
			continue
		}
		nsRecords := make([]string, 0, len(servers))
		extra := make([]ZoneRecord, 0, len(servers)*3)
		labelMap := make(map[string][]infra.NameServer)
		for _, ns := range servers {
			nsRecords = append(nsRecords, ensureDot(ns.FQDN))
			if ns.IPv4 != "" {
				extra = append(extra, ZoneRecord{
					Name:  relativeLabel(ns.FQDN, base),
					Type:  "A",
					Value: ns.IPv4,
				})
			}
			label := strings.TrimSpace(ns.NSLabel)
			if label == "" {
				label = "dns"
			}
			labelMap[label] = append(labelMap[label], ns)
		}
		for label, nsByLabel := range labelMap {
			for _, ns := range nsByLabel {
				extra = append(extra, ZoneRecord{
					Name:  label,
					Type:  "NS",
					Value: ensureDot(ns.FQDN),
				})
			}
		}
		zone := ZoneFile{
			Domain:     base,
			TTL:        300,
			PrimaryNS:  ensureDot(servers[0].FQDN),
			AdminEmail: fmt.Sprintf("admin.%s.", strings.TrimSuffix(base, ".")),
			Serial:     serial,
			NSRecords:  uniqueStrings(nsRecords),
			Extra:      dedupeRecords(extra),
		}
		zones = append(zones, zone)
		for label, nsByLabel := range labelMap {
			if len(nsByLabel) == 0 {
				continue
			}
			labelDomain := fmt.Sprintf("%s.%s", label, base)
			labelNSRecords := make([]string, 0, len(nsByLabel))
			labelExtras := make([]ZoneRecord, 0, len(nsByLabel))
			for _, ns := range nsByLabel {
				labelNSRecords = append(labelNSRecords, ensureDot(ns.FQDN))
				if ns.IPv4 != "" {
					labelExtras = append(labelExtras, ZoneRecord{
						Name:  relativeLabel(ns.FQDN, labelDomain),
						Type:  "A",
						Value: ns.IPv4,
					})
				}
			}
			labelZone := ZoneFile{
				Domain:     labelDomain,
				TTL:        300,
				PrimaryNS:  ensureDot(nsByLabel[0].FQDN),
				AdminEmail: fmt.Sprintf("admin.%s.", strings.TrimSuffix(labelDomain, ".")),
				Serial:     serial,
				NSRecords:  uniqueStrings(labelNSRecords),
				Extra:      dedupeRecords(labelExtras),
			}
			zones = append(zones, labelZone)
		}
	}
	return zones
}

// Render writes OpenResty configs with template.
func (g *OpenRestyGenerator) Render() error {
	domains, err := g.Store.GetDomains()
	if err != nil {
		return err
	}
	nodes, err := g.Store.GetNodes()
	if err != nil {
		return err
	}
	nodeMap := make(map[string]models.Node, len(nodes))
	for _, node := range nodes {
		nodeMap[node.ID] = node
	}
	edges, err := g.Infra.EdgeIPs()
	if err != nil {
		return err
	}
	edgeHealth, err := g.Store.GetEdgeHealthMap()
	if err != nil {
		return err
	}
	hasHealthData := len(edgeHealth) > 0
	healthyEdges := filterHealthyEdges(edges, edgeHealth)
	localInfo := g.localNodeInfo()
	if stored, ok := nodeMap[localInfo.NodeID]; ok {
		if len(localInfo.IPs) == 0 {
			localInfo.IPs = append([]string{}, stored.IPs...)
		}
		if len(localInfo.NSIPs) == 0 {
			localInfo.NSIPs = append([]string{}, stored.NSIPs...)
		}
		if len(localInfo.EdgeIPs) == 0 {
			localInfo.EdgeIPs = append([]string{}, stored.EdgeIPs...)
		}
	}
	localEdges := g.localEdgeIPs(localInfo)
	localEdgeSet := make(map[string]struct{}, len(localEdges))
	for _, ip := range localEdges {
		if ip == "" {
			continue
		}
		localEdgeSet[ip] = struct{}{}
	}
	filteredLocal := filterHealthyEdges(localEdges, edgeHealth)
	if len(filteredLocal) == 0 && len(localEdges) > 0 {
		filteredLocal = append([]string{}, localEdges...)
	}
	if len(filteredLocal) == 0 {
		filteredLocal = healthyEdges
		if len(filteredLocal) == 0 && !hasHealthData {
			filteredLocal = edges
		}
	}
	edgeIPs := uniqueStrings(filteredLocal)
	if len(edgeIPs) == 0 && !hasHealthData {
		edgeIPs = uniqueStrings(localEdges)
	}
	if len(edgeIPs) == 0 && !hasHealthData {
		edgeIPs = uniqueStrings(edges)
	}
	if err := os.MkdirAll(g.OutputDir, 0o755); err != nil {
		return err
	}
	sitesDir := filepath.Join(g.OutputDir, "sites-enabled")
	if err := os.MkdirAll(sitesDir, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(sitesDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			_ = os.Remove(filepath.Join(sitesDir, entry.Name()))
		}
	}

	certsDir := filepath.Join(g.OutputDir, "certs")
	if err := os.MkdirAll(certsDir, 0o750); err != nil {
		return err
	}
	challengesRoot := filepath.Join(g.OutputDir, "challenges")
	if err := os.MkdirAll(challengesRoot, 0o755); err != nil {
		return err
	}
	originPullDir := filepath.Join(g.OutputDir, "origin-pull")
	if err := os.MkdirAll(originPullDir, 0o750); err != nil {
		return err
	}
	placeholderDir := filepath.Join(g.OutputDir, "placeholders")
	if err := os.MkdirAll(placeholderDir, 0o755); err != nil {
		return err
	}
	if entries, err := os.ReadDir(placeholderDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if strings.HasSuffix(entry.Name(), ".html") {
				_ = os.Remove(filepath.Join(placeholderDir, entry.Name()))
			}
		}
	}

	nsList, err := g.Infra.ActiveNameServers()
	if err != nil {
		return err
	}
	nsIPs := make(map[string]struct{}, len(nsList))
	for _, ns := range nsList {
		if ns.IPv4 == "" {
			continue
		}
		nsIPs[ns.IPv4] = struct{}{}
	}

	tmpl, err := template.ParseFiles(g.SitesTmpl)
	if err != nil {
		return err
	}

	limitReqPerIP := envIntPositive("EDGE_LIMIT_REQ_PER_IP", 120)
	limitReqPerIPBurst := envIntPositive("EDGE_LIMIT_REQ_BURST", limitReqPerIP*2)
	limitReqPerHost := envIntPositive("EDGE_LIMIT_REQ_PER_HOST", 8000)
	limitReqPerHostBurst := envIntPositive("EDGE_LIMIT_REQ_HOST_BURST", limitReqPerHost*2)
	limitConnPerIP := envIntPositive("EDGE_LIMIT_CONN_PER_IP", 200)
	clientMaxBody := envStringOrDefault("EDGE_CLIENT_MAX_BODY", "64m")
	limitReqNoDelay := envBool("EDGE_LIMIT_REQ_NODELAY", false)

	edgeCacheCfg := extensions.EdgeCacheRuntimeConfig{}
	placeholderCfg := extensions.PlaceholderRuntimeConfig{}
	if g.Extensions != nil {
		cfg, err := g.Extensions.EdgeCacheConfig()
		if err != nil {
			return err
		}
		edgeCacheCfg = cfg
		pcfg, err := g.Extensions.PlaceholderConfig()
		if err != nil {
			return err
		}
		placeholderCfg = pcfg
	}
	if edgeCacheCfg.Enabled {
		cachePath := strings.TrimSpace(edgeCacheCfg.Path)
		if cachePath != "" {
			if err := os.MkdirAll(cachePath, 0o755); err != nil {
				return fmt.Errorf("create cache dir %s: %w", cachePath, err)
			}
		}
	}
	cacheUseStaleGlobal := strings.Join(edgeCacheCfg.UseStale, " ")
	cacheBypassCookies := edgeCacheCfg.BypassCookies

	edgeUsage := make(map[string]bool)
	for _, domain := range domains {
		if !domain.Proxied {
			continue
		}
		mode := domain.TLS.Mode
		if domain.TLS.UseRecommended && domain.TLS.RecommendedMode != "" {
			mode = domain.TLS.RecommendedMode
		}
		if mode == "" {
			mode = models.EncryptionFlexible
		}
		hasCertMaterial := domain.TLS.Certificate != nil && domain.TLS.Certificate.CertChainPEM != ""
		baseName := sanitizeFileName(domain.Domain)
		certPath := filepath.Join(certsDir, fmt.Sprintf("%s.crt", baseName))
		keyPath := filepath.Join(certsDir, fmt.Sprintf("%s.key", baseName))
		if hasCertMaterial {
			if err := os.WriteFile(certPath, []byte(domain.TLS.Certificate.CertChainPEM), 0o644); err != nil {
				return err
			}
			if err := os.WriteFile(keyPath, []byte(domain.TLS.Certificate.PrivateKeyPEM), 0o600); err != nil {
				return err
			}
		} else {
			_ = os.Remove(certPath)
			_ = os.Remove(keyPath)
		}
		challengeDir := filepath.Join(challengesRoot, baseName)
		if err := syncChallenges(challengeDir, domain.TLS.Challenges); err != nil {
			return err
		}
		originPullCert := ""
		originPullKey := ""
		if domain.TLS.OriginPullSecret != nil {
			originPullCertPath := filepath.Join(originPullDir, fmt.Sprintf("%s-origin.crt", baseName))
			originPullKeyPath := filepath.Join(originPullDir, fmt.Sprintf("%s-origin.key", baseName))
			if err := os.WriteFile(originPullCertPath, []byte(domain.TLS.OriginPullSecret.CertificatePEM), 0o644); err != nil {
				return err
			}
			if err := os.WriteFile(originPullKeyPath, []byte(domain.TLS.OriginPullSecret.PrivateKeyPEM), 0o600); err != nil {
				return err
			}
			originPullCert = originPullCertPath
			originPullKey = originPullKeyPath
		} else {
			_ = os.Remove(filepath.Join(originPullDir, fmt.Sprintf("%s-origin.crt", baseName)))
			_ = os.Remove(filepath.Join(originPullDir, fmt.Sprintf("%s-origin.key", baseName)))
		}

		originAddress := strings.TrimSpace(domain.OriginIP)
		placeholderActive := false
		if placeholderCfg.Enabled && originAddress == "" {
			placeholderActive = true
		} else if originAddress == "" {
			fmt.Printf("OpenResty generator: skipping domain %s, origin IP not set and placeholder disabled\n", domain.Domain)
			continue
		}
		placeholderFileName := fmt.Sprintf("%s.html", baseName)
		if placeholderActive {
			html := renderPlaceholderHTML(domain.Domain, placeholderCfg)
			if err := os.WriteFile(filepath.Join(placeholderDir, placeholderFileName), []byte(html), 0o644); err != nil {
				return err
			}
		} else {
			_ = os.Remove(filepath.Join(placeholderDir, placeholderFileName))
		}

		originScheme := "http"
		verifyOrigin := false
		if originAddress != "" {
			if mode == models.EncryptionFull || mode == models.EncryptionFullStrict || mode == models.EncryptionStrictOriginPull {
				originScheme = "https"
			}
			if mode == models.EncryptionFullStrict || mode == models.EncryptionStrictOriginPull {
				verifyOrigin = true
			}
		}
		strictOrigin := originAddress != "" && mode == models.EncryptionStrictOriginPull && originPullCert != "" && originPullKey != ""
		serveTLS := hasCertMaterial && mode != models.EncryptionOff
		redirectHTTP := serveTLS && mode != models.EncryptionFlexible
		needsTLS := mode != models.EncryptionOff
		pendingTLS := needsTLS && !hasCertMaterial

		placeholderCert := ""
		placeholderKey := ""
		if pendingTLS {
			certPath, keyPath, err := ensurePlaceholderCertificate(g.DataDir, domain.Domain)
			if err != nil {
				return err
			}
			placeholderCert = certPath
			placeholderKey = keyPath
		}

		assignedIP := strings.TrimSpace(domain.Edge.AssignedIP)
		if assignedIP == "" {
			continue
		}
		if _, ok := localEdgeSet[assignedIP]; !ok {
			continue
		}
		edgeUsage[assignedIP] = true
		proxyPass := ""
		if originAddress != "" && !placeholderActive {
			proxyPass = fmt.Sprintf("%s://%s", originScheme, originAddress)
		}
		challengeUpstream := "http://127.0.0.1:8080"
		if domain.TLS.LockNodeID != "" && domain.TLS.LockNodeID != localInfo.NodeID {
			if node, ok := nodeMap[domain.TLS.LockNodeID]; ok {
				if endpoint := strings.TrimSuffix(node.APIEndpoint, "/"); endpoint != "" {
					challengeUpstream = endpoint
				}
			}
		}
		serverHeader := ""
		if g.Extensions != nil {
			if header, ok, err := g.Extensions.ServerHeaderForDomain(domain.Domain); err != nil {
				fmt.Printf("OpenResty generator: server header lookup for %s failed: %v\n", domain.Domain, err)
			} else if ok {
				serverHeader = header
			}
		}
		cacheActive := edgeCacheCfg.Enabled && !placeholderActive
		cacheUseStale := strings.Join(edgeCacheCfg.UseStale, " ")
		cacheVersion := domain.CacheVersion
		if cacheVersion <= 0 {
			cacheVersion = 1
		}
		mainTTLSeconds := jitterSeconds(edgeCacheCfg.BaseTTLSeconds, edgeCacheCfg.TTLJitterPct, domain.Domain)
		if mainTTLSeconds <= 0 {
			mainTTLSeconds = 86400
		}
		notFoundTTLSeconds := edgeCacheCfg.NotFoundTTL
		if notFoundTTLSeconds <= 0 {
			notFoundTTLSeconds = 600
		}
		errorTTLSeconds := edgeCacheCfg.ErrorTTL
		if errorTTLSeconds <= 0 {
			errorTTLSeconds = 60
		}
		var cacheTTLMain, cacheTTLNotFound, cacheTTLError string
		if cacheActive {
			cacheTTLMain = formatTTLSeconds(mainTTLSeconds)
			cacheTTLNotFound = formatTTLSeconds(jitterSeconds(notFoundTTLSeconds, edgeCacheCfg.TTLJitterPct/2, domain.Domain))
			cacheTTLError = formatTTLSeconds(jitterSeconds(errorTTLSeconds, edgeCacheCfg.TTLJitterPct/2, domain.Domain))
		}
		data := map[string]interface{}{
			"Domain":              domain.Domain,
			"EdgeIP":              assignedIP,
			"OriginIP":            originAddress,
			"ProxyPass":           proxyPass,
			"Mode":                mode,
			"HasCertificate":      serveTLS,
			"CertPath":            certPath,
			"KeyPath":             keyPath,
			"ChallengeDir":        challengeDir,
			"RedirectHTTP":        redirectHTTP,
			"PendingTLS":          pendingTLS,
			"FallbackLabel":       baseName,
			"OriginIsHTTPS":       originScheme == "https",
			"OriginAvailable":     originAddress != "",
			"VerifyOrigin":        verifyOrigin,
			"OriginServerName":    domain.Domain,
			"StrictOriginPull":    strictOrigin,
			"OriginPullCert":      originPullCert,
			"OriginPullKey":       originPullKey,
			"ChallengeProxy":      challengeUpstream,
			"PlaceholderCert":     placeholderCert,
			"PlaceholderKey":      placeholderKey,
			"PlaceholderEnabled":  placeholderActive,
			"PlaceholderTitle":    placeholderCfg.Title,
			"PlaceholderSubtitle": placeholderCfg.Subtitle,
			"PlaceholderMessage":  placeholderCfg.Message,
			"PlaceholderSupport": map[string]string{
				"url":  placeholderCfg.SupportURL,
				"text": placeholderCfg.SupportText,
			},
			"PlaceholderFooter":  placeholderCfg.Footer,
			"PlaceholderRoot":    placeholderDir,
			"PlaceholderFile":    placeholderFileName,
			"LimitConnPerIP":     limitConnPerIP,
			"LimitReqPerIP":      limitReqPerIP,
			"LimitReqBurstIP":    limitReqPerIPBurst,
			"LimitReqPerHost":    limitReqPerHost,
			"LimitReqBurstHost":  limitReqPerHostBurst,
			"LimitReqNoDelay":    limitReqNoDelay,
			"CacheEnabled":       cacheActive,
			"CacheZone":          edgeCacheCfg.ZoneName,
			"CacheAddStatus":     edgeCacheCfg.AddStatusHeader,
			"CacheUseStale":      cacheUseStale,
			"CacheMinUses":       edgeCacheCfg.MinUses,
			"CacheBypassCookies": edgeCacheCfg.BypassCookies,
			"CachePath":          edgeCacheCfg.Path,
			"ServerHeader":       serverHeader,
			"CacheVersion":       cacheVersion,
			"CacheTTLMain":       cacheTTLMain,
			"CacheTTLNotFound":   cacheTTLNotFound,
			"CacheTTLError":      cacheTTLError,
		}
		buf := bytes.Buffer{}
		if err := tmpl.Execute(&buf, data); err != nil {
			return err
		}
		file := filepath.Join(sitesDir, fmt.Sprintf("%s@%s.conf", sanitizeFileName(domain.Domain), strings.ReplaceAll(assignedIP, ":", "_")))
		if err := os.WriteFile(file, buf.Bytes(), 0o644); err != nil {
			return err
		}
	}

	for _, ip := range localEdges {
		if _, used := edgeUsage[ip]; used {
			continue
		}
		if err := writeEdgeStub(sitesDir, ip); err != nil {
			return err
		}
	}

	nginxTemplate, err := template.ParseFiles(g.NginxTmpl)
	if err != nil {
		return err
	}
	nginxData := map[string]interface{}{
		"SitesDir":           sitesDir,
		"LimitReqPerIP":      limitReqPerIP,
		"LimitReqPerHost":    limitReqPerHost,
		"LimitConnPerIP":     limitConnPerIP,
		"ClientMaxBodySize":  clientMaxBody,
		"LimitReqNoDelay":    limitReqNoDelay,
		"CacheEnabled":       edgeCacheCfg.Enabled,
		"CachePath":          edgeCacheCfg.Path,
		"CacheLevels":        edgeCacheCfg.Levels,
		"CacheZoneName":      edgeCacheCfg.ZoneName,
		"CacheKeysZone":      edgeCacheCfg.KeysZoneSize,
		"CacheMaxSize":       edgeCacheCfg.MaxSize,
		"CacheInactive":      edgeCacheCfg.Inactive,
		"CacheUseStale":      cacheUseStaleGlobal,
		"CacheMinUses":       edgeCacheCfg.MinUses,
		"CacheBypassCookies": cacheBypassCookies,
	}
	buf := bytes.Buffer{}
	if err := nginxTemplate.Execute(&buf, nginxData); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(g.OutputDir, "nginx.conf"), buf.Bytes(), 0o644)
}

func jitterSeconds(base int, percent int, key string) int {
	if base <= 0 || percent <= 0 {
		if base <= 0 {
			return base
		}
		return base
	}
	maxJitter := base * percent / 100
	if maxJitter <= 0 {
		return base
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(strings.TrimSpace(key))))
	span := int(h.Sum32()%(uint32(2*maxJitter)+1)) - maxJitter
	ttl := base + span
	if ttl < 1 {
		ttl = 1
	}
	return ttl
}

func formatTTLSeconds(seconds int) string {
	if seconds <= 0 {
		return "0s"
	}
	if seconds%86400 == 0 {
		return fmt.Sprintf("%dd", seconds/86400)
	}
	if seconds%3600 == 0 {
		return fmt.Sprintf("%dh", seconds/3600)
	}
	if seconds%60 == 0 {
		return fmt.Sprintf("%dm", seconds/60)
	}
	return fmt.Sprintf("%ds", seconds)
}

func renderPlaceholderHTML(domain string, cfg extensions.PlaceholderRuntimeConfig) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		domain = "your-domain.example"
	}
	escDomain := htmltmpl.HTMLEscapeString(domain)
	title := strings.TrimSpace(cfg.Title)
	if title == "" {
		title = "Domain delegated to aki.cloud"
	}
	subtitle := strings.TrimSpace(cfg.Subtitle)
	message := strings.TrimSpace(cfg.Message)
	supportURL := strings.TrimSpace(cfg.SupportURL)
	supportText := strings.TrimSpace(cfg.SupportText)
	footer := strings.TrimSpace(cfg.Footer)

	b := strings.Builder{}
	b.WriteString("<!doctype html>\n")
	b.WriteString("<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>")
	b.WriteString(htmltmpl.HTMLEscapeString(title))
	b.WriteString(" • ")
	b.WriteString(escDomain)
	b.WriteString("</title>\n<style>\n")
	b.WriteString("body{margin:0;font-family:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px;}\n")
	b.WriteString(".card{max-width:540px;width:100%;background:rgba(15,23,42,0.8);border:1px solid rgba(148,163,184,0.2);border-radius:18px;padding:40px;box-shadow:0 24px 70px rgba(15,23,42,0.45);}\n")
	b.WriteString(".badge{display:inline-block;padding:4px 10px;border-radius:999px;background:rgba(59,130,246,0.15);color:#60a5fa;font-size:12px;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:16px;}\n")
	b.WriteString("h1{margin:0;font-size:28px;line-height:1.2;}\n")
	b.WriteString("p{margin:12px 0;font-size:16px;line-height:1.6;color:#cbd5f5;}\n")
	b.WriteString(".domain{margin-top:18px;font-size:20px;font-weight:600;color:#f8fafc;}\n")
	b.WriteString(".footer{margin-top:32px;font-size:13px;color:rgba(148,163,184,0.8);}\n")
	b.WriteString(".cta{display:inline-flex;margin-top:20px;padding:10px 18px;border-radius:10px;border:1px solid rgba(96,165,250,0.4);color:#93c5fd;text-decoration:none;font-weight:600;transition:all .2s ease;}\n")
	b.WriteString(".cta:hover{background:rgba(96,165,250,0.1);border-color:#93c5fd;color:#bfdbfe;}\n")
	b.WriteString("</style>\n</head>\n<body>\n<div class=\"card\">\n<span class=\"badge\">aki.cloud</span>\n<h1>")
	b.WriteString(htmltmpl.HTMLEscapeString(title))
	b.WriteString("</h1>\n")
	if subtitle != "" {
		b.WriteString("<p>")
		b.WriteString(htmltmpl.HTMLEscapeString(subtitle))
		b.WriteString("</p>\n")
	}
	b.WriteString("<p class=\"domain\">")
	b.WriteString(escDomain)
	b.WriteString("</p>\n")
	if message != "" {
		b.WriteString("<p>")
		b.WriteString(htmltmpl.HTMLEscapeString(message))
		b.WriteString("</p>\n")
	}
	if supportURL != "" {
		linkText := supportText
		if linkText == "" {
			linkText = "Configure origin"
		}
		b.WriteString("<a class=\"cta\" href=\"")
		b.WriteString(htmltmpl.HTMLEscapeString(supportURL))
		b.WriteString("\" target=\"_blank\" rel=\"noopener noreferrer\">")
		b.WriteString(htmltmpl.HTMLEscapeString(linkText))
		b.WriteString("</a>\n")
	}
	if footer != "" {
		b.WriteString("<div class=\"footer\">")
		b.WriteString(htmltmpl.HTMLEscapeString(footer))
		b.WriteString("</div>\n")
	}
	b.WriteString("</div>\n</body>\n</html>")
	return b.String()
}

type localEdgeNode struct {
	NodeID       string   `json:"node_id"`
	Name         string   `json:"name"`
	IPs          []string `json:"ips"`
	NSIPs        []string `json:"ns_ips"`
	EdgeIPs      []string `json:"edge_ips"`
	NSLabel      string   `json:"ns_label"`
	NSBaseDomain string   `json:"ns_base_domain"`
}

func (g *OpenRestyGenerator) localNodeInfo() localEdgeNode {
	return loadLocalNodeInfo(g.DataDir)
}

func (g *CoreDNSGenerator) localNodeInfo() localEdgeNode {
	return loadLocalNodeInfo(g.DataDir)
}

func envIntPositive(key string, def int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return def
	}
	num, err := strconv.Atoi(value)
	if err != nil || num <= 0 {
		return def
	}
	return num
}

func envStringOrDefault(key string, def string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return def
	}
	return value
}

func envBool(key string, def bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return def
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func writeEdgeStub(dir string, ip string) error {
	file := filepath.Join(dir, fmt.Sprintf("_stub@%s.conf", strings.ReplaceAll(ip, ":", "_")))
	data := fmt.Sprintf(`server {
    listen %s:80;
    server_name _;

    location / {
        return 204;
    }
}
`, ip)
	return os.WriteFile(file, []byte(data), 0o644)
}

func ensurePlaceholderCertificate(dataDir, domain string) (string, string, error) {
	base := sanitizeFileName(domain)
	certDir := filepath.Join(dataDir, "openresty", "placeholder")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return "", "", err
	}
	certPath := filepath.Join(certDir, fmt.Sprintf("%s.crt", base))
	keyPath := filepath.Join(certDir, fmt.Sprintf("%s.key", base))

	if validPlaceholder(certPath, domain) && fileExists(keyPath) {
		return certPath, keyPath, nil
	}

	certPEM, keyPEM, err := generatePlaceholderCertificate(domain)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func validPlaceholder(path string, domain string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	if time.Now().After(cert.NotAfter.Add(-24 * time.Hour)) {
		return false
	}
	expected := map[string]struct{}{
		strings.ToLower(domain):        {},
		strings.ToLower("*." + domain): {},
	}
	for _, name := range cert.DNSNames {
		delete(expected, strings.ToLower(name))
	}
	return len(expected) == 0
}

func generatePlaceholderCertificate(domain string) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:  []string{domain, "*." + domain},
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(90 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func syncChallenges(dir string, challenges []models.ACMEChallenge) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	valid := make(map[string]string, len(challenges))
	now := time.Now().UTC()
	for _, ch := range challenges {
		if ch.ChallengeType != "" && ch.ChallengeType != challengeTypeHTTP {
			continue
		}
		if ch.Token == "" || ch.KeyAuth == "" {
			continue
		}
		if !ch.ExpiresAt.IsZero() && ch.ExpiresAt.Before(now.Add(-time.Minute)) {
			continue
		}
		valid[ch.Token] = ch.KeyAuth
	}
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
				continue
			}
			name := entry.Name()
			if _, ok := valid[name]; !ok {
				_ = os.Remove(filepath.Join(dir, name))
			}
		}
	}
	for token, keyAuth := range valid {
		if err := os.WriteFile(filepath.Join(dir, token), []byte(keyAuth), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func loadLocalNodeInfo(dataDir string) localEdgeNode {
	path := filepath.Join(dataDir, "cluster", "node.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return localEdgeNode{}
	}
	var node localEdgeNode
	if err := json.Unmarshal(data, &node); err != nil {
		return localEdgeNode{}
	}
	return node
}

func (g *OpenRestyGenerator) localEdgeIPs(node localEdgeNode) []string {
	if len(node.EdgeIPs) > 0 {
		return uniqueStrings(trimAndFilter(node.EdgeIPs))
	}
	ns := make(map[string]struct{}, len(node.NSIPs))
	for _, ip := range node.NSIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		ns[ip] = struct{}{}
	}
	edges := make([]string, 0, len(node.IPs))
	for _, raw := range node.IPs {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		if _, ok := ns[ip]; ok {
			continue
		}
		edges = append(edges, ip)
	}
	if len(edges) == 0 {
		edges = append(edges, trimAndFilter(node.NSIPs)...)
	}
	return uniqueStrings(edges)
}

func ensureDot(input string) string {
	if strings.HasSuffix(input, ".") {
		return input
	}
	return input + "."
}

func relativeLabel(fqdn string, zone string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")
	if fqdn == zone {
		return "@"
	}
	suffix := "." + zone
	if zone != "" && strings.HasSuffix(fqdn, suffix) {
		return strings.TrimSuffix(fqdn, suffix)
	}
	return fqdn
}

func sanitizeFileName(name string) string {
	cleaned := strings.ReplaceAll(name, "..", ".")
	cleaned = strings.ReplaceAll(cleaned, string(os.PathSeparator), "-")
	cleaned = strings.ReplaceAll(cleaned, " ", "-")
	return cleaned
}

func filterHealthyEdges(all []string, health map[string]models.EdgeHealthStatus) []string {
	const staleThreshold = 10 * time.Minute
	if len(all) == 0 {
		return all
	}
	filtered := make([]string, 0, len(all))
	for _, ip := range all {
		status, ok := health[ip]
		if !ok || status.LastChecked.IsZero() {
			filtered = append(filtered, ip)
			continue
		}
		if status.Healthy {
			filtered = append(filtered, ip)
			continue
		}
		if time.Since(status.LastChecked) > staleThreshold {
			filtered = append(filtered, ip)
		}
	}
	return filtered
}

func trimAndFilter(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func dedupeRecords(records []ZoneRecord) []ZoneRecord {
	if len(records) == 0 {
		return records
	}
	seen := make(map[string]struct{}, len(records))
	out := make([]ZoneRecord, 0, len(records))
	for _, r := range records {
		if r.Name == "" {
			r.Name = "@"
		}
		key := strings.Join([]string{r.Name, r.Type, r.Value}, "\x1f")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}
	return out
}
