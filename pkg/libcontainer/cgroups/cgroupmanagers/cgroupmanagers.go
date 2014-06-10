package cgroupmanagers

import (
	"github.com/dotcloud/docker/pkg/libcontainer/cgroups"
	"github.com/dotcloud/docker/pkg/libcontainer/cgroups/fs"
	"github.com/dotcloud/docker/pkg/libcontainer/cgroups/systemd"
)

func NewManager() cgroups.CgroupManager {
	if systemd.UseSystemd() {
		return systemd.NewManager()
	}
  return fs.NewManager()
}
