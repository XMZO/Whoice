package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/data/publicsuffixes"
	"github.com/xmzo/whoice/services/lookup-api/internal/httpapi"
	"github.com/xmzo/whoice/services/lookup-api/internal/lookup"
	"github.com/xmzo/whoice/services/lookup-api/internal/observability"
	"github.com/xmzo/whoice/services/lookup-api/internal/plugin"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		healthcheck()
		return
	}

	cfg := config.Load()
	if cfg.PSLAutoUpdate {
		if err := publicsuffixes.UpdateFromRemote(context.Background(), cfg.DataDir, cfg.PSLURL, cfg.PSLUpdateTimeout); err != nil {
			log.Printf("public suffix auto update failed: %v", err)
		} else {
			log.Printf("public suffix list updated from %s", cfg.PSLURL)
		}
	}

	pluginRegistry := plugin.NewRegistry()
	plugin.RegisterDefaults(pluginRegistry, cfg)

	service := lookup.NewService(cfg, pluginRegistry.Providers(), pluginRegistry.ParserRegistry())
	stats := observability.NewStats()
	server := httpapi.New(cfg, service, pluginRegistry.Plugins(), stats)

	log.Printf("whoice lookup-api listening on %s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, server.Handler()); err != nil {
		log.Fatal(err)
	}
}

func healthcheck() {
	addr := os.Getenv("WHOICE_API_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = "http://" + addr
	}
	client := http.Client{Timeout: 3 * time.Second}
	res, err := client.Get(strings.TrimRight(addr, "/") + "/api/health")
	if err != nil {
		os.Exit(1)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		os.Exit(1)
	}
}
