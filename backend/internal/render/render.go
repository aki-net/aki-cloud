package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"aki-cloud/backend/internal/infra"
	"aki-cloud/backend/internal/models"
	"aki-cloud/backend/internal/store"
)

// CoreDNSGenerator renders CoreDNS configuration using templates.
type CoreDNSGenerator struct {
	Store    *store.Store
	Infra    *infra.Controller
	DataDir  string
	Template string
}

// OpenRestyGenerator renders OpenResty configs.
type OpenRestyGenerator struct {
	Store     *store.Store
	Infra     *infra.Controller
	DataDir   string
	NginxTmpl string
	SitesTmpl string
	OutputDir string
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

// Render writes CoreDNS Corefile and zone files to data directory.
func (g *CoreDNSGenerator) Render() error {
	domains, err := g.Store.GetDomains()
	if err != nil {
		return err
	}
	nsList, err := g.Infra.ActiveNameServers()
	if err != nil {
		return err
	}
	local := g.localNodeInfo()
	filteredNS := make([]infra.NameServer, 0, len(nsList))
	if local.NodeID != "" {
		for _, ns := range nsList {
			if ns.NodeID == local.NodeID {
				filteredNS = append(filteredNS, ns)
			}
		}
	}
	if len(filteredNS) == 0 {
		filteredNS = nsList
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
	serial := now.Format("2006010215")
	primaryNS := "ns1.local.invalid."
	if len(activeNS) > 0 {
		primaryNS = ensureDot(activeNS[0].FQDN)
	}
	for _, domain := range domains {
		ttl := domain.TTL
		if ttl <= 0 {
			ttl = 60
		}
		arecords := []string{}
		if domain.Proxied && len(healthyEdges) > 0 {
			arecords = append(arecords, healthyEdges...)
		} else {
			arecords = append(arecords, domain.OriginIP)
		}
		if len(arecords) == 0 {
			arecords = []string{domain.OriginIP}
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
	data := struct {
		NameServers []infra.NameServer
		Zones       []zoneMeta
		ZonesDir    string
	}{
		NameServers: filteredNS,
		Zones:       zones,
		ZonesDir:    zonesDir,
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
	edges, err := g.Infra.EdgeIPs()
	if err != nil {
		return err
	}
	edgeHealth, err := g.Store.GetEdgeHealthMap()
	if err != nil {
		return err
	}
	healthyEdges := filterHealthyEdges(edges, edgeHealth)
	localInfo := g.localNodeInfo()
	localEdges := g.localEdgeIPs(localInfo)
	nsList, err := g.Infra.ActiveNameServers()
	if err != nil {
		return err
	}
	nsIPs := map[string]struct{}{}
	for _, ns := range nsList {
		nsIPs[ns.IPv4] = struct{}{}
	}
	filteredLocal := filterHealthyEdges(localEdges, edgeHealth)
	if len(filteredLocal) == 0 {
		filteredLocal = localEdges
	}
	if len(filteredLocal) == 0 {
		filteredLocal = healthyEdges
		if len(filteredLocal) == 0 {
			filteredLocal = edges
		}
	}
	edgeIPs := uniqueStrings(filteredLocal)
	if len(edgeIPs) == 0 {
		edgeIPs = uniqueStrings(localEdges)
	}
	if len(edgeIPs) == 0 {
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

	tmpl, err := template.ParseFiles(g.SitesTmpl)
	if err != nil {
		return err
	}

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
		hasCert := domain.TLS.Certificate != nil && domain.TLS.Certificate.CertChainPEM != ""
		baseName := sanitizeFileName(domain.Domain)
		certPath := filepath.Join(certsDir, fmt.Sprintf("%s.crt", baseName))
		keyPath := filepath.Join(certsDir, fmt.Sprintf("%s.key", baseName))
		if hasCert {
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

		originScheme := "http"
		verifyOrigin := false
		if mode == models.EncryptionFull || mode == models.EncryptionFullStrict || mode == models.EncryptionStrictOriginPull {
			originScheme = "https"
		}
		if mode == models.EncryptionFullStrict || mode == models.EncryptionStrictOriginPull {
			verifyOrigin = true
		}
		strictOrigin := mode == models.EncryptionStrictOriginPull && originPullCert != "" && originPullKey != ""
		redirectHTTP := hasCert && mode != models.EncryptionFlexible
		proxyPass := fmt.Sprintf("%s://%s", originScheme, domain.OriginIP)
		for _, edgeIP := range edgeIPs {
			if _, isNS := nsIPs[edgeIP]; isNS {
				continue
			}
			data := map[string]interface{}{
				"Domain":           domain.Domain,
				"EdgeIP":           edgeIP,
				"OriginIP":         domain.OriginIP,
				"ProxyPass":        proxyPass,
				"Mode":             mode,
				"HasCertificate":   hasCert,
				"CertPath":         certPath,
				"KeyPath":          keyPath,
				"ChallengeDir":     challengeDir,
				"RedirectHTTP":     redirectHTTP,
				"OriginIsHTTPS":    originScheme == "https",
				"VerifyOrigin":     verifyOrigin,
				"OriginServerName": domain.Domain,
				"StrictOriginPull": strictOrigin,
				"OriginPullCert":   originPullCert,
				"OriginPullKey":    originPullKey,
			}
			buf := bytes.Buffer{}
			if err := tmpl.Execute(&buf, data); err != nil {
				return err
			}
			file := filepath.Join(sitesDir, fmt.Sprintf("%s@%s.conf", sanitizeFileName(domain.Domain), strings.ReplaceAll(edgeIP, ":", "_")))
			if err := os.WriteFile(file, buf.Bytes(), 0o644); err != nil {
				return err
			}
		}
	}

	nginxTemplate, err := template.ParseFiles(g.NginxTmpl)
	if err != nil {
		return err
	}
	nginxData := map[string]interface{}{
		"SitesDir": sitesDir,
	}
	buf := bytes.Buffer{}
	if err := nginxTemplate.Execute(&buf, nginxData); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(g.OutputDir, "nginx.conf"), buf.Bytes(), 0o644)
}

type localEdgeNode struct {
	NodeID string   `json:"node_id"`
	IPs    []string `json:"ips"`
	NSIPs  []string `json:"ns_ips"`
}

func (g *OpenRestyGenerator) localNodeInfo() localEdgeNode {
	return loadLocalNodeInfo(g.DataDir)
}

func (g *CoreDNSGenerator) localNodeInfo() localEdgeNode {
	return loadLocalNodeInfo(g.DataDir)
}

func syncChallenges(dir string, challenges []models.ACMEChallenge) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	valid := make(map[string]string, len(challenges))
	now := time.Now().UTC()
	for _, ch := range challenges {
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
	ns := make(map[string]struct{}, len(node.NSIPs))
	for _, ip := range node.NSIPs {
		ns[ip] = struct{}{}
	}
	edges := make([]string, 0, len(node.IPs))
	for _, ip := range node.IPs {
		if _, ok := ns[ip]; ok {
			continue
		}
		if ip != "" {
			edges = append(edges, ip)
		}
	}
	return edges
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
		if !ok {
			filtered = append(filtered, ip)
			continue
		}
		if status.Healthy {
			filtered = append(filtered, ip)
			continue
		}
		if status.LastChecked.IsZero() {
			filtered = append(filtered, ip)
			continue
		}
		if time.Since(status.LastChecked) > staleThreshold {
			filtered = append(filtered, ip)
		}
	}
	return filtered
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
