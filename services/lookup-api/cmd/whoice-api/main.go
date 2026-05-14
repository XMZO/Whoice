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
	runtimecfg "github.com/xmzo/whoice/services/lookup-api/internal/runtime"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		healthcheck()
		return
	}

	cfg, err := config.LoadWithError()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if cfg.ConfigCreated {
		log.Printf("created default config at %s", cfg.ConfigPath)
	}
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
	service.StartBackground(context.Background())
	stats := observability.NewStats()
	server, err := httpapi.NewStrict(cfg, service, pluginRegistry.Plugins(), stats)
	if err != nil {
		log.Fatalf("build runtime: %v", err)
	}
	runtimecfg.StartConfigWatcher(context.Background(), server, runtimecfg.Builder{Addr: cfg.Addr, ConfigPath: cfg.ConfigPath}, runtimecfg.DefaultWatchInterval)

	log.Printf("whoice lookup-api listening on %s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, server.Handler()); err != nil {
		log.Fatal(err)
	}
}

func healthcheck() {
	if envAddr := strings.TrimSpace(os.Getenv("WHOICE_HEALTHCHECK_ADDR")); envAddr != "" {
		if checkHealth(envAddr) {
			return
		}
		os.Exit(1)
	}
	addr := config.Default().Addr
	if cfg, err := config.LoadWithError(); err == nil && strings.TrimSpace(cfg.Addr) != "" {
		addr = cfg.Addr
	}
	if checkHealth(addr) {
		return
	}
	os.Exit(1)
}

func checkHealth(addr string) bool {
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = "http://" + addr
	}
	client := http.Client{Timeout: 3 * time.Second}
	res, err := client.Get(strings.TrimRight(addr, "/") + "/api/health")
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode >= 200 && res.StatusCode < 300
}
