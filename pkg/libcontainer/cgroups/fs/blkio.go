package fs

import (
	"path/filepath"

	"github.com/dotcloud/docker/pkg/libcontainer/cgroups"
)

type blkioGroup struct {
}

func (s *blkioGroup) Set(d *data) error {
	// we just want to join this group even though we don't set anything
	if _, err := d.join("blkio"); err != nil && err != cgroups.ErrNotFound {
		return err
	}
	return nil
}

func (s *blkioGroup) Remove(d *data) error {
	return removePath(d.path("blkio"))
}

/*
examples:

    blkio.sectors
    8:0 6792

    blkio.io_service_bytes
    8:0 Read 1282048
    8:0 Write 2195456
    8:0 Sync 2195456
    8:0 Async 1282048
    8:0 Total 3477504
    Total 3477504

    blkio.io_serviced
    8:0 Read 124
    8:0 Write 104
    8:0 Sync 104
    8:0 Async 124
    8:0 Total 228
    Total 228

    blkio.io_queued
    8:0 Read 0
    8:0 Write 0
    8:0 Sync 0
    8:0 Async 0
    8:0 Total 0
    Total 0
*/

func (s *blkioGroup) GetStats(d *data, stats *cgroups.Stats) error {
	var blkioStats []cgroups.BlkioStatEntry
	var err error
	path, err := d.path("blkio")
	if err != nil {
		return err
	}

	if blkioStats, err = cgroups.GetBlkioStatFromFile(filepath.Join(path, "blkio.sectors_recursive")); err != nil {
    return err
	}
	stats.BlkioStats.SectorsRecursive = blkioStats

	if blkioStats, err = cgroups.GetBlkioStatFromFile(filepath.Join(path, "blkio.io_service_bytes_recursive")); err != nil {
    return err
	}
	stats.BlkioStats.IoServiceBytesRecursive = blkioStats

	if blkioStats, err = cgroups.GetBlkioStatFromFile(filepath.Join(path, "blkio.io_serviced_recursive")); err != nil {
    return err
	}
	stats.BlkioStats.IoServicedRecursive = blkioStats

	if blkioStats, err = cgroups.GetBlkioStatFromFile(filepath.Join(path, "blkio.io_queued_recursive")); err != nil {
    return err
	}
	stats.BlkioStats.IoQueuedRecursive = blkioStats

	return nil
}
