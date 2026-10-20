//go:build unix

package admin

import (
	"os"
	"syscall"
)

// matchOwner gives path the owner of dir when running as root, so a reset run through
// `docker compose exec` stays readable by the unprivileged API process.
func matchOwner(path, dir string) {
	if os.Geteuid() != 0 {
		return
	}
	info, err := os.Stat(dir)
	if err != nil {
		return
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(path, int(stat.Uid), int(stat.Gid))
	}
}
