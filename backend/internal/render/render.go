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
	"io"
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
	Extensions   *extensions.Service
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
	Records    []ZoneRecord
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

type renderRedirect struct {
	Source string
	Status int
	Return string
}

func buildRedirectReturn(rule models.DomainRedirectRule) string {
	target := strings.TrimSpace(rule.Target)
	if target == "" {
		return ""
	}
	trimmed := func(base string) string {
		base = strings.TrimSpace(base)
		if base == "" {
			return ""
		}
		// Avoid trailing slashes before appending nginx variables such as $uri.
		return strings.TrimRight(base, "/")
	}
	if rule.PreservePath && rule.PreserveQuery {
		base := trimmed(target)
		if base == "" {
			return "$request_uri"
		}
		return base + "$request_uri"
	}
	if rule.PreservePath {
		base := trimmed(target)
		if base == "" {
			return "$uri"
		}
		return base + "$uri"
	}
	if rule.PreserveQuery {
		return target + "$is_args$args"
	}
	return target
}

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
	var (
		vanitySets       map[string]extensions.VanityNameServerSet
		vanityZoneExtras map[string][]ZoneRecord
	)
	if g.Extensions != nil {
		cfg, err := g.Extensions.VanityNSConfig()
		if err != nil {
			return err
		}
		if cfg.Enabled {
			vanitySets = make(map[string]extensions.VanityNameServerSet, len(domains))
			vanityZoneExtras = make(map[string][]ZoneRecord)
			zoneName := cfg.ZoneFQDN()
			for _, domain := range domains {
				set, err := g.Extensions.VanityNameServersForDomain(domain.Domain, nsList)
				if err != nil {
					return err
				}
				if len(set.Anycast) == 0 && len(set.Domain) == 0 {
					continue
				}
				domainKey := strings.ToLower(strings.TrimSuffix(domain.Domain, "."))
				vanitySets[domainKey] = set
				if zoneName == "" {
					continue
				}
				for _, ns := range set.Anycast {
					name := strings.TrimSpace(ns.Name)
					ip := strings.TrimSpace(ns.IPv4)
					if name == "" || ip == "" {
						continue
					}
					label := relativeLabel(name, zoneName)
					vanityZoneExtras[zoneName] = append(vanityZoneExtras[zoneName], ZoneRecord{
						Name:  label,
						Type:  "A",
						Value: ip,
					})
				}
			}
		}
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
		zoneRecords := append([]ZoneRecord{}, challengeExtras...)
		assignedIP := strings.TrimSpace(domain.Edge.AssignedIP)
		if domain.Proxied {
			if assignedIP != "" {
				fmt.Printf("DEBUG: Domain %s using assigned IP %s\n", domain.Domain, assignedIP)
			} else {
				fmt.Printf("DEBUG: Domain %s has no assigned IP (Edge: %+v)\n", domain.Domain, domain.Edge)
			}
		} else {
			fmt.Printf("DEBUG: Domain %s is not proxied\n", domain.Domain)
		}
		var usedOriginFallback bool
		if len(domain.DNSRecords) == 0 {
			fallbackRecords, usedOrigin := renderFallbackZoneRecords(domain, assignedIP)
			zoneRecords = append(zoneRecords, fallbackRecords...)
			usedOriginFallback = usedOrigin
		} else {
			customRecords, usedOrigin := renderCustomDNSRecords(domain, assignedIP)
			zoneRecords = append(zoneRecords, customRecords...)
			usedOriginFallback = usedOrigin
		}
		if usedOriginFallback && strings.TrimSpace(domain.OriginIP) != "" {
			fmt.Printf("DEBUG: Domain %s falling back to origin IP %s\n", domain.Domain, domain.OriginIP)
		}
		nsRecords := make([]string, 0, len(activeNS))
		for _, ns := range activeNS {
			nsRecords = append(nsRecords, ensureDot(ns.FQDN))
		}
		domainKey := strings.ToLower(strings.TrimSuffix(domain.Domain, "."))
		if vanity, ok := vanitySets[domainKey]; ok {
			for _, ns := range vanity.Anycast {
				name := strings.TrimSpace(ns.Name)
				if name == "" {
					continue
				}
				nsRecords = append(nsRecords, ensureDot(name))
			}
			for _, ns := range vanity.Domain {
				name := strings.TrimSpace(ns.Name)
				ip := strings.TrimSpace(ns.IPv4)
				if name != "" {
					nsRecords = append(nsRecords, ensureDot(name))
				}
				if name != "" && ip != "" {
					zoneRecords = append(zoneRecords, ZoneRecord{
						Name:  relativeLabel(name, domain.Domain),
						Type:  "A",
						Value: ip,
					})
				}
			}
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
			NSRecords:  uniqueStrings(nsRecords),
			Records:    dedupeRecords(zoneRecords),
		}
		zoneFiles = append(zoneFiles, zone)
	}

	infraZones := g.buildInfrastructureZones(activeNS, serial, vanityZoneExtras)
	zoneFiles = append(zoneFiles, infraZones...)

	for _, zone := range zoneFiles {
		fmt.Printf("CoreDNS generator: writing zone for %s (%d NS, %d records)\n", zone.Domain, len(zone.NSRecords), len(zone.Records))
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
{{- range .Records}}
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

func (g *CoreDNSGenerator) buildInfrastructureZones(nsList []infra.NameServer, serial string, vanityExtras map[string][]ZoneRecord) []ZoneFile {
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
		if len(vanityExtras) > 0 {
			if records, ok := vanityExtras[strings.TrimSuffix(base, ".")]; ok {
				extra = append(extra, records...)
			}
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
			Records:    dedupeRecords(extra),
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
				Records:    dedupeRecords(append(labelExtras, vanityExtras[labelDomain]...)),
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
	domainLookup := make(map[string]*models.DomainRecord, len(domains))
	for i := range domains {
		key := strings.ToLower(domains[i].Domain)
		domainLookup[key] = &domains[i]
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
	placeholderSourceDir := filepath.Join(filepath.Dir(g.SitesTmpl), "placeholders")
	if !filepath.IsAbs(placeholderSourceDir) {
		if abs, err := filepath.Abs(placeholderSourceDir); err == nil {
			placeholderSourceDir = abs
		}
	}
	if err := syncPlaceholders(placeholderSourceDir, placeholderDir); err != nil {
		return err
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
	searchBotCfg := extensions.SearchBotRuntimeConfig{}
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
		sbCfg, err := g.Extensions.SearchBotConfig()
		if err != nil {
			return err
		}
		searchBotCfg = sbCfg
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

	searchBotTemplateBots := make([]map[string]string, 0, len(searchBotCfg.Bots))
	if searchBotCfg.Enabled {
		for _, bot := range searchBotCfg.Bots {
			key := strings.TrimSpace(bot.Key)
			regex := strings.TrimSpace(bot.Regex)
			if key == "" || regex == "" {
				continue
			}
			searchBotTemplateBots = append(searchBotTemplateBots, map[string]string{
				"Key":   key,
				"Regex": regex,
			})
		}
	}

	if err := ensurePlaceholderDefault(placeholderDir, "delegated.html", placeholderCfg); err != nil {
		return err
	}

	wafSourceDir := filepath.Join(filepath.Dir(g.SitesTmpl), "waf-placeholders")
	if !filepath.IsAbs(wafSourceDir) {
		if abs, err := filepath.Abs(wafSourceDir); err == nil {
			wafSourceDir = abs
		}
	}

	wafPlaceholderDir := filepath.Join(g.DataDir, "openresty", "waf-placeholders")
	if err := os.MkdirAll(wafPlaceholderDir, 0o755); err != nil {
		return fmt.Errorf("create waf placeholder dir %s: %w", wafPlaceholderDir, err)
	}
	if err := syncWAFPlaceholders(wafSourceDir, wafPlaceholderDir); err != nil {
		return err
	}
	if err := ensureWAFPlaceholder(wafPlaceholderDir, "block.html", placeholderCfg); err != nil {
		return err
	}

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
		originMode := mode
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
		var aliasPrimary *models.DomainRecord
		isAliasDomain := domain.Role == models.DomainRoleAlias && domain.Alias != nil
		isRedirectDomain := domain.Role == models.DomainRoleRedirect
		if isAliasDomain {
			if primary, ok := domainLookup[strings.ToLower(domain.Alias.Target)]; ok && primary.Role == models.DomainRolePrimary {
				if addr := strings.TrimSpace(primary.OriginIP); addr != "" {
					originAddress = addr
				}
				aliasPrimary = primary
			} else {
				fmt.Printf("OpenResty generator: alias %s target %s missing or not primary\n", domain.Domain, domain.Alias.Target)
			}
		}
		if aliasPrimary != nil {
			parentMode := aliasPrimary.TLS.Mode
			if aliasPrimary.TLS.UseRecommended && aliasPrimary.TLS.RecommendedMode != "" {
				parentMode = aliasPrimary.TLS.RecommendedMode
			}
			if parentMode != "" {
				originMode = parentMode
			}
		}
		if originMode == "" {
			originMode = models.EncryptionFlexible
		}
		if isRedirectDomain {
			originAddress = ""
		}
		placeholderActive := false
		if placeholderCfg.Enabled && originAddress == "" {
			placeholderActive = true
		} else if originAddress == "" {
			fmt.Printf("OpenResty generator: skipping domain %s, origin IP not set and placeholder disabled\n", domain.Domain)
			continue
		}
		placeholderFileName := fmt.Sprintf("%s.html", baseName)
		placeholderPath := filepath.Join(placeholderDir, placeholderFileName)
		if placeholderActive {
			if _, err := os.Stat(placeholderPath); os.IsNotExist(err) {
				html := renderPlaceholderHTML(domain.Domain, placeholderCfg)
				if err := os.WriteFile(placeholderPath, []byte(html), 0o644); err != nil {
					return err
				}
			}
		}

		originScheme := "http"
		verifyOrigin := false
		if originAddress != "" {
			if originMode == models.EncryptionFull || originMode == models.EncryptionFullStrict || originMode == models.EncryptionStrictOriginPull {
				originScheme = "https"
			}
			if originMode == models.EncryptionFullStrict || originMode == models.EncryptionStrictOriginPull {
				verifyOrigin = true
			}
		}
		strictOrigin := originAddress != "" && originMode == models.EncryptionStrictOriginPull && originPullCert != "" && originPullKey != ""
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
		if aliasPrimary != nil && aliasPrimary.CacheVersion > 0 {
			cacheVersion = aliasPrimary.CacheVersion
		}
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
		var domainRule *models.DomainRedirectRule
		pathRules := make([]models.DomainRedirectRule, 0)
		if len(domain.RedirectRules) > 0 {
			for _, rule := range domain.RedirectRules {
				ruleCopy := rule
				if ruleCopy.IsDomainRule() {
					if domainRule == nil {
						domainRule = &ruleCopy
					}
					continue
				}
				if ruleCopy.IsPathRule() {
					pathRules = append(pathRules, ruleCopy)
				}
			}
		}
		hasDomainRedirect := domainRule != nil
		if hasDomainRedirect || isRedirectDomain {
			redirectHTTP = false
		}
		var domainRedirect renderRedirect
		var domainRedirectPtr *renderRedirect
		if hasDomainRedirect {
			domainRedirect = renderRedirect{
				Status: domainRule.StatusCode,
				Return: buildRedirectReturn(*domainRule),
			}
			domainRedirectPtr = &domainRedirect
		}
		renderPathRedirects := make([]renderRedirect, 0)
		if !hasDomainRedirect && len(pathRules) > 0 {
			for _, rule := range pathRules {
				renderPathRedirects = append(renderPathRedirects, renderRedirect{
					Source: rule.Source,
					Status: rule.StatusCode,
					Return: buildRedirectReturn(rule),
				})
			}
		}
		hasPathRedirects := len(renderPathRedirects) > 0
		wafDomainFile := fmt.Sprintf("%s.html", sanitizeFileName(domain.Domain))
		originServerName := domain.Domain
		upstreamHost := "$host"
		if aliasPrimary != nil {
			originServerName = aliasPrimary.Domain
			upstreamHost = aliasPrimary.Domain
		}
		serverNames := buildServerNames(domain)
		if len(serverNames) == 0 {
			serverNames = []string{strings.TrimSuffix(domain.Domain, ".")}
		}
		data := map[string]interface{}{
			"Domain":              domain.Domain,
			"ServerNames":         strings.Join(serverNames, " "),
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
			"OriginServerName":    originServerName,
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
			"PlaceholderFooter":        placeholderCfg.Footer,
			"PlaceholderRoot":          placeholderDir,
			"PlaceholderFile":          placeholderFileName,
			"PlaceholderDefaultFile":   "delegated.html",
			"WAFPlaceholderRoot":       wafPlaceholderDir,
			"WAFPlaceholderFile":       "block.html",
			"WAFPlaceholderDomainFile": wafDomainFile,
			"LimitConnPerIP":           limitConnPerIP,
			"LimitReqPerIP":            limitReqPerIP,
			"LimitReqBurstIP":          limitReqPerIPBurst,
			"LimitReqPerHost":          limitReqPerHost,
			"LimitReqBurstHost":        limitReqPerHostBurst,
			"LimitReqNoDelay":          limitReqNoDelay,
			"CacheEnabled":             cacheActive,
			"CacheZone":                edgeCacheCfg.ZoneName,
			"CacheAddStatus":           edgeCacheCfg.AddStatusHeader,
			"CacheUseStale":            cacheUseStale,
			"CacheMinUses":             edgeCacheCfg.MinUses,
			"CacheBypassCookies":       edgeCacheCfg.BypassCookies,
			"CachePath":                edgeCacheCfg.Path,
			"ServerHeader":             serverHeader,
			"CacheVersion":             cacheVersion,
			"CacheTTLMain":             cacheTTLMain,
			"CacheTTLNotFound":         cacheTTLNotFound,
			"CacheTTLError":            cacheTTLError,
			"SearchBotLoggingEnabled":  searchBotCfg.Enabled,
			"SearchBotLogFile":         searchBotCfg.LogFile,
			"WAFEnabled":               domain.WAF.IsActive(),
			"WAFGooglebotOnly":         domain.WAF.IsActive() && domain.WAF.HasPreset(models.WAFPresetAllowGooglebotOnly),
			"IsRedirectDomain":         isRedirectDomain,
			"HasDomainRedirect":        hasDomainRedirect,
			"DomainRedirect":           domainRedirectPtr,
			"HasPathRedirects":         hasPathRedirects,
			"PathRedirects":            renderPathRedirects,
			"UpstreamHost":             upstreamHost,
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
		"SearchBotLogging": map[string]interface{}{
			"Enabled": searchBotCfg.Enabled,
			"LogDir":  searchBotCfg.LogDir,
			"LogFile": searchBotCfg.LogFile,
			"GeoFile": searchBotCfg.GeoFile,
			"Bots":    searchBotTemplateBots,
		},
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

func ensureWAFPlaceholder(dir, file string, cfg extensions.PlaceholderRuntimeConfig) error {
	path := filepath.Join(dir, file)
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat waf placeholder: %w", err)
	}
	content := renderWAFPlaceholderHTML(cfg)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write waf placeholder: %w", err)
	}
	return nil
}

func ensurePlaceholderDefault(dir, file string, cfg extensions.PlaceholderRuntimeConfig) error {
	path := filepath.Join(dir, file)
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat placeholder default: %w", err)
	}
	html := renderPlaceholderHTML("", cfg)
	if err := os.WriteFile(path, []byte(html), 0o644); err != nil {
		return fmt.Errorf("write placeholder default: %w", err)
	}
	return nil
}

func syncPlaceholders(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read placeholder dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".html") {
			continue
		}
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())
		if err := copyFile(srcPath, dstPath); err != nil {
			return err
		}
	}
	return nil
}

func syncWAFPlaceholders(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read waf placeholder dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())
		if err := copyFile(srcPath, dstPath); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer srcFile.Close()

	tmpPath := dst + ".tmp"
	dstFile, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", tmpPath, err)
	}
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		dstFile.Close()
		return fmt.Errorf("copy %s to %s: %w", src, dst, err)
	}
	if err := dstFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpPath, dst, err)
	}
	return nil
}

func renderWAFPlaceholderHTML(cfg extensions.PlaceholderRuntimeConfig) string {
	title := strings.TrimSpace(cfg.Title)
	if title == "" {
		title = "Access restricted"
	}
	subtitle := strings.TrimSpace(cfg.Subtitle)
	if subtitle == "" {
		subtitle = "Only verified Googlebot traffic is allowed to reach this site."
	}
	message := strings.TrimSpace(cfg.Message)
	if message == "" {
		message = "Your request has been blocked by the aki.cloud Web Application Firewall preset."
	}
	supportURL := strings.TrimSpace(cfg.SupportURL)
	supportText := strings.TrimSpace(cfg.SupportText)
	if supportURL != "" && supportText == "" {
		supportText = supportURL
	}
	footer := strings.TrimSpace(cfg.Footer)
	if footer == "" {
		footer = "Secured by aki.cloud"
	}

	b := strings.Builder{}
	b.WriteString("<!doctype html>\n")
	b.WriteString("<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>")
	b.WriteString(htmltmpl.HTMLEscapeString(title))
	b.WriteString("</title>\n<style>\n")
	b.WriteString("body{margin:0;font-family:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:radial-gradient(circle at 20% 20%,rgba(71,97,215,0.25),transparent 55%),#050816;color:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:32px;}\n")
	b.WriteString(".card{max-width:520px;width:100%;background:rgba(12,20,43,0.82);border:1px solid rgba(148,163,184,0.16);border-radius:22px;padding:44px;box-shadow:0 30px 90px rgba(5,8,22,0.55);backdrop-filter:blur(14px);}\n")
	b.WriteString(".badge{display:inline-flex;align-items:center;gap:8px;font-size:12px;letter-spacing:0.08em;text-transform:uppercase;padding:6px 12px;border-radius:999px;background:rgba(239,68,68,0.12);color:#fca5a5;border:1px solid rgba(248,113,113,0.35);margin-bottom:22px;}\n")
	b.WriteString("h1{margin:0 0 16px;font-size:30px;line-height:1.2;}\n")
	b.WriteString("p{margin:0 0 22px;font-size:16px;line-height:1.65;color:rgba(226,232,240,0.82);}\n")
	b.WriteString(".support{font-size:14px;color:rgba(148,163,184,0.78);}\n")
	b.WriteString(".support a{color:#60a5fa;text-decoration:none;font-weight:600;}\n")
	b.WriteString("footer{margin-top:32px;font-size:12px;letter-spacing:0.08em;text-transform:uppercase;color:rgba(148,163,184,0.6);}\n")
	b.WriteString("</style>\n</head>\n<body>\n<div class=\"card\">\n<span class=\"badge\">Web Application Firewall</span>\n<h1>")
	b.WriteString(htmltmpl.HTMLEscapeString(title))
	b.WriteString("</h1>\n")
	b.WriteString("<p>")
	b.WriteString(htmltmpl.HTMLEscapeString(subtitle))
	b.WriteString("</p>\n")
	b.WriteString("<p>")
	b.WriteString(htmltmpl.HTMLEscapeString(message))
	b.WriteString("</p>\n")
	if supportURL != "" {
		b.WriteString("<p class=\"support\">For assistance visit <a href=\"")
		b.WriteString(htmltmpl.HTMLEscapeString(supportURL))
		b.WriteString("\" target=\"_blank\" rel=\"noopener noreferrer\">")
		b.WriteString(htmltmpl.HTMLEscapeString(supportText))
		b.WriteString("</a>.</p>\n")
	}
	if footer != "" {
		b.WriteString("<footer>")
		b.WriteString(htmltmpl.HTMLEscapeString(footer))
		b.WriteString("</footer>\n")
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

func buildServerNames(domain models.DomainRecord) []string {
	base := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain.Domain)), ".")
	names := make([]string, 0, len(domain.DNSRecords)+1)
	if base != "" {
		names = append(names, base)
	}
	if domain.Proxied && len(domain.DNSRecords) > 0 {
		for _, rec := range domain.DNSRecords {
			if !rec.Proxied {
				continue
			}
			host := dnsRecordHost(base, rec.Name)
			if host == "" {
				continue
			}
			names = append(names, host)
		}
	}
	return uniqueStrings(names)
}

func dnsRecordHost(base string, name string) string {
	label := strings.ToLower(strings.TrimSpace(name))
	base = strings.TrimSpace(base)
	if label == "" || label == "@" {
		return base
	}
	label = strings.TrimSuffix(label, ".")
	if base != "" && label == base {
		return base
	}
	if base != "" && strings.HasSuffix(label, "."+base) {
		return label
	}
	if label == "*" {
		if base == "" {
			return "*"
		}
		return "*." + base
	}
	if strings.HasPrefix(label, "*.") {
		trimmed := strings.TrimPrefix(label, "*.")
		if trimmed == "" {
			if base == "" {
				return "*"
			}
			return "*." + base
		}
		if base != "" && strings.HasSuffix(trimmed, "."+base) {
			return label
		}
		if base == "" {
			return "*." + trimmed
		}
		return "*." + trimmed + "." + base
	}
	if base == "" {
		return label
	}
	return label + "." + base
}

func renderFallbackZoneRecords(domain models.DomainRecord, assignedIP string) ([]ZoneRecord, bool) {
	records := make([]ZoneRecord, 0, 2)
	origin := strings.TrimSpace(domain.OriginIP)
	if domain.Proxied && assignedIP != "" {
		records = append(records, ZoneRecord{
			Name:  "@",
			Type:  "A",
			Value: assignedIP,
		})
	}
	if len(records) == 0 && origin != "" {
		records = append(records, ZoneRecord{
			Name:  "@",
			Type:  "A",
			Value: origin,
		})
		return records, true
	}
	return records, false
}

func renderCustomDNSRecords(domain models.DomainRecord, assignedIP string) ([]ZoneRecord, bool) {
	records := make([]ZoneRecord, 0, len(domain.DNSRecords))
	origin := strings.TrimSpace(domain.OriginIP)
	usedOrigin := false
	apexHost := strings.TrimSuffix(domain.Domain, ".")
	for _, rec := range domain.DNSRecords {
		name := strings.TrimSpace(rec.Name)
		if name == "" || name == "@" {
			name = "@"
		}
		switch rec.Type {
		case models.DNSRecordTypeA:
			value := strings.TrimSpace(rec.Content)
			if value == "@" {
				value = ""
			}
			if rec.Proxied && domain.Proxied {
				if assignedIP != "" {
					records = append(records, ZoneRecord{Name: name, Type: "A", Value: assignedIP})
				} else if origin != "" {
					records = append(records, ZoneRecord{Name: name, Type: "A", Value: origin})
					usedOrigin = true
				}
			} else if value != "" {
				records = append(records, ZoneRecord{Name: name, Type: "A", Value: value})
			}
		case models.DNSRecordTypeAAAA:
			value := strings.TrimSpace(rec.Content)
			if rec.Proxied && domain.Proxied {
				if assignedIP != "" {
					records = append(records, ZoneRecord{Name: name, Type: "A", Value: assignedIP})
				} else if origin != "" {
					records = append(records, ZoneRecord{Name: name, Type: "A", Value: origin})
					usedOrigin = true
				}
			} else if value != "" {
				records = append(records, ZoneRecord{Name: name, Type: "AAAA", Value: value})
			}
		case models.DNSRecordTypeCNAME:
			target := strings.TrimSpace(rec.Content)
			if target == "@" {
				target = apexHost
			}
			if rec.Proxied && domain.Proxied {
				if assignedIP != "" {
					records = append(records, ZoneRecord{Name: name, Type: "A", Value: assignedIP})
				} else if origin != "" {
					records = append(records, ZoneRecord{Name: name, Type: "A", Value: origin})
					usedOrigin = true
				}
			} else if target != "" {
				records = append(records, ZoneRecord{Name: name, Type: "CNAME", Value: ensureDot(target)})
			}
		case models.DNSRecordTypeMX:
			target := strings.TrimSpace(rec.Content)
			if target == "@" {
				target = apexHost
			}
			if target == "" {
				continue
			}
			priority := 0
			if rec.Priority != nil {
				priority = *rec.Priority
			}
			records = append(records, ZoneRecord{
				Name:  name,
				Type:  "MX",
				Value: fmt.Sprintf("%d %s", priority, ensureDot(target)),
			})
		case models.DNSRecordTypeNS:
			target := strings.TrimSpace(rec.Content)
			if target == "@" {
				target = apexHost
			}
			if target == "" {
				continue
			}
			records = append(records, ZoneRecord{
				Name:  name,
				Type:  "NS",
				Value: ensureDot(target),
			})
		case models.DNSRecordTypeTXT:
			if strings.TrimSpace(rec.Content) == "" {
				continue
			}
			records = append(records, ZoneRecord{
				Name:  name,
				Type:  "TXT",
				Value: formatTXTValue(rec.Content),
			})
		default:
			content := strings.TrimSpace(rec.Content)
			if content == "@" {
				switch rec.Type {
				case models.DNSRecordTypeHTTPS, models.DNSRecordTypeSVCB, models.DNSRecordTypeURI, models.DNSRecordTypePTR:
					content = apexHost
				}
			}
			if content == "" {
				continue
			}
			records = append(records, ZoneRecord{
				Name:  name,
				Type:  strings.ToUpper(string(rec.Type)),
				Value: content,
			})
		}
	}
	return records, usedOrigin
}

func formatTXTValue(content string) string {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return `""`
	}
	if strings.HasPrefix(trimmed, `"`) && strings.HasSuffix(trimmed, `"`) && len(trimmed) >= 2 {
		return trimmed
	}
	return fmt.Sprintf(`"%s"`, trimmed)
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
