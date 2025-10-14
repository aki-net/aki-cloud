package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"aki-cloud/backend/internal/extensions"
	"aki-cloud/backend/internal/infra"
	"aki-cloud/backend/internal/render"
	"aki-cloud/backend/internal/store"
)

func main() {
	var dataDir string
	var corednsTemplate string
	var nginxTemplate string
	var sitesTemplate string
	var openrestyOut string

	// Read NS configuration from environment
	nsLabel := os.Getenv("NS_LABEL")
	if nsLabel == "" {
		nsLabel = "dns" // default
	}
	nsBaseDomain := os.Getenv("NS_BASE_DOMAIN")
	if nsBaseDomain == "" {
		nsBaseDomain = "aki.cloud" // default
	}

	flag.StringVar(&dataDir, "data-dir", "./data", "Path to data directory")
	flag.StringVar(&corednsTemplate, "coredns-template", "./coredns/Corefile.tmpl", "CoreDNS template path")
	flag.StringVar(&nginxTemplate, "nginx-template", "./openresty/nginx.conf.tmpl", "OpenResty nginx.conf template")
	flag.StringVar(&sitesTemplate, "sites-template", "./openresty/sites.tmpl", "OpenResty site template")
	flag.StringVar(&openrestyOut, "openresty-output", "./data/openresty", "Directory to write OpenResty config")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		log.Fatalf("component required: coredns, openresty, all")
	}
	component := args[0]

	store, err := store.New(dataDir)
	if err != nil {
		log.Fatalf("init store: %v", err)
	}

	infraCtl := infra.New(store, dataDir)
	extSvc := extensions.New(store, "")

	switch component {
	case "coredns":
		gen := render.CoreDNSGenerator{Store: store, Infra: infraCtl, DataDir: dataDir, Template: corednsTemplate, NSLabel: nsLabel, NSBaseDomain: nsBaseDomain}
		if err := gen.Render(); err != nil {
			log.Fatalf("render coredns: %v", err)
		}
	case "openresty":
		gen := render.OpenRestyGenerator{Store: store, Infra: infraCtl, Extensions: extSvc, DataDir: dataDir, NginxTmpl: nginxTemplate, SitesTmpl: sitesTemplate, OutputDir: openrestyOut, NSLabel: nsLabel, NSBaseDomain: nsBaseDomain}
		if err := gen.Render(); err != nil {
			log.Fatalf("render openresty: %v", err)
		}
	case "all":
		corednsGen := render.CoreDNSGenerator{Store: store, Infra: infraCtl, DataDir: dataDir, Template: corednsTemplate, NSLabel: nsLabel, NSBaseDomain: nsBaseDomain}
		if err := corednsGen.Render(); err != nil {
			log.Fatalf("render coredns: %v", err)
		}
		openrestyGen := render.OpenRestyGenerator{Store: store, Infra: infraCtl, Extensions: extSvc, DataDir: dataDir, NginxTmpl: nginxTemplate, SitesTmpl: sitesTemplate, OutputDir: openrestyOut, NSLabel: nsLabel, NSBaseDomain: nsBaseDomain}
		if err := openrestyGen.Render(); err != nil {
			log.Fatalf("render openresty: %v", err)
		}
	default:
		log.Fatalf("unknown component %q", component)
	}

	if err := writeMarker(component, dataDir); err != nil {
		log.Printf("warning: unable to write marker: %v", err)
	}
}

func writeMarker(component string, dataDir string) error {
	markerDir := filepath.Join(dataDir, "cluster")
	if err := os.MkdirAll(markerDir, 0o755); err != nil {
		return err
	}
	marker := filepath.Join(markerDir, fmt.Sprintf("last_render_%s", component))
	return os.WriteFile(marker, []byte(fmt.Sprintf("%s\n", component)), 0o644)
}
