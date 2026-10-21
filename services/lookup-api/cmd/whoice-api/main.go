package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/admin"
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
	if len(os.Args) > 1 && os.Args[1] == "reset-admin-password" {
		resetAdminPassword()
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
	adminManager, generated, err := admin.Open(cfg.DataDir)
	if err != nil {
		log.Fatalf("admin credentials: %v", err)
	}
	server.SetAdmin(adminManager)
	if generated != "" {
		log.Printf("admin panel password generated: %s (sign in at /admin and change it there; reset with `whoice-api reset-admin-password`)", generated)
	} else if adminManager.PasswordFromEnv() {
		log.Printf("admin panel password is set by %s", admin.PasswordEnv)
	}
	runtimecfg.StartConfigWatcher(context.Background(), server, runtimecfg.Builder{Addr: cfg.Addr, ConfigPath: cfg.ConfigPath}, runtimecfg.DefaultWatchInterval)

	// As PID 1 in a container the process ignores SIGTERM unless it handles
	// it, which made `docker compose up` wait 10s before killing it.
	httpServer := &http.Server{Addr: cfg.Addr, Handler: server.Handler()}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		log.Printf("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}()

	log.Printf("whoice lookup-api listening on %s", cfg.Addr)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func resetAdminPassword() {
	cfg, err := config.LoadWithError()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	password, err := admin.ResetPassword(cfg.DataDir)
	if err != nil {
		log.Fatalf("reset admin password: %v", err)
	}
	fmt.Printf("New admin panel password: %s\n", password)
	if os.Getenv(admin.PasswordEnv) != "" {
		fmt.Printf("Note: %s is set and takes priority over the stored password.\n", admin.PasswordEnv)
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
