package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/httpapi"
	"github.com/xmzo/whoice/services/lookup-api/internal/lookup"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"github.com/xmzo/whoice/services/lookup-api/internal/plugin"
)

const (
	DefaultWatchInterval = time.Second
	reloadDebounce       = 250 * time.Millisecond
)

type Builder struct {
	Addr       string
	ConfigPath string
}

type Snapshot struct {
	Config  config.Config
	Service *lookup.Service
	Plugins []model.PluginInfo
}

func (b Builder) Build() (Snapshot, error) {
	cfg, err := config.LoadExistingWithError(b.ConfigPath)
	if err != nil {
		return Snapshot{}, err
	}
	if strings.TrimSpace(b.Addr) != "" && strings.TrimSpace(cfg.Addr) != strings.TrimSpace(b.Addr) {
		return Snapshot{}, fmt.Errorf("server.addr changed from %q to %q; restart the API process to change the listen address", b.Addr, cfg.Addr)
	}
	pluginRegistry := plugin.NewRegistry()
	plugin.RegisterDefaults(pluginRegistry, cfg)
	service := lookup.NewService(cfg, pluginRegistry.Providers(), pluginRegistry.ParserRegistry())
	return Snapshot{
		Config:  cfg,
		Service: service,
		Plugins: pluginRegistry.Plugins(),
	}, nil
}

func StartConfigWatcher(ctx context.Context, srv *httpapi.Server, builder Builder, interval time.Duration) {
	if srv == nil {
		return
	}
	path := strings.TrimSpace(srv.ConfigStatus().Path)
	if path == "" {
		log.Print("config hot reload disabled: no config file path")
		return
	}
	if interval <= 0 {
		interval = DefaultWatchInterval
	}
	go watch(ctx, path, interval, func(attemptedAt time.Time) {
		time.Sleep(reloadDebounce)
		snapshot, err := builder.Build()
		if err != nil {
			srv.RecordConfigReloadError(path, attemptedAt, err)
			log.Printf("config reload failed; keeping last valid config: %v", err)
			return
		}
		if err := srv.ApplyRuntime(snapshot.Config, snapshot.Service, snapshot.Plugins, attemptedAt); err != nil {
			srv.RecordConfigReloadError(path, attemptedAt, err)
			log.Printf("config reload failed; keeping last valid config: %v", err)
			return
		}
		log.Printf("config reloaded from %s", snapshot.Config.ConfigPath)
	}, fileStamp{})
	log.Printf("config hot reload watching %s", path)
}

func watch(ctx context.Context, path string, interval time.Duration, onChange func(time.Time), last fileStamp) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	check := func(now time.Time) {
		next := readStamp(path)
		if !sameStamp(last, next) {
			last = next
			onChange(now.UTC())
		}
	}
	check(time.Now().UTC())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			check(now)
		}
	}
}

type fileStamp struct {
	Exists  bool
	Size    int64
	ModUnix int64
	Hash    string
	Error   string
}

func readStamp(path string) fileStamp {
	info, err := os.Stat(path)
	if err != nil {
		stamp := fileStamp{Error: err.Error()}
		if errors.Is(err, os.ErrNotExist) {
			stamp.Exists = false
		}
		return stamp
	}
	stamp := fileStamp{
		Exists:  true,
		Size:    info.Size(),
		ModUnix: info.ModTime().UnixNano(),
	}
	body, err := os.ReadFile(path)
	if err != nil {
		stamp.Error = err.Error()
		return stamp
	}
	sum := sha256.Sum256(body)
	stamp.Hash = hex.EncodeToString(sum[:])
	return stamp
}

func sameStamp(left, right fileStamp) bool {
	return left.Exists == right.Exists &&
		left.Size == right.Size &&
		left.ModUnix == right.ModUnix &&
		left.Hash == right.Hash &&
		left.Error == right.Error
}
