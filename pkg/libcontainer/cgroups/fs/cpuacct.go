package fs

import (
	"github.com/dotcloud/docker/pkg/libcontainer/cgroups"
)

type cpuacctGroup struct {
}

func (s *cpuacctGroup) Set(d *data) error {
	// we just want to join this group even though we don't set anything
	if _, err := d.join("cpuacct"); err != nil && err != cgroups.ErrNotFound {
		return err
	}
	return nil
}

func (s *cpuacctGroup) Remove(d *data) error {
	return removePath(d.path("cpuacct"))
}

func (s *cpuacctGroup) GetStats(d *data, stats *cgroups.Stats) error {
	path, err := d.path("cpuacct")
	if err != nil {
		return err
	}
  return cgroups.GetCpuUsageStats(path, stats)
}
