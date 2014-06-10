// +build !linux

package systemd

import (
	"fmt"

	"github.com/dotcloud/docker/pkg/libcontainer/cgroups"
)

type manager struct {}

func NewManager() *manager {
  return &manager{}
}

func UseSystemd() bool {
	return false
}

func (m *manager) Apply(c *cgroups.Cgroup, pid int) (cgroups.ActiveCgroup, error) {
	return nil, fmt.Errorf("Systemd not supported")
}

func (m *manager) GetPids(c *cgroups.Cgroup) ([]int, error) {
	return nil, fmt.Errorf("Systemd not supported")
}

func (m *manager) Freeze(c *cgroups.Cgroup, state cgroups.FreezerState) error {
	return fmt.Errorf("Systemd not supported")
}

func (m *manager) GetStats(c *cgroups.Cgroup) (*cgroups.Stats, error) {
	return nil, fmt.Errorf("Systemd not supported")
}
