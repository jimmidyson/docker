package lxc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dotcloud/docker/daemon/execdriver"
	"github.com/dotcloud/docker/pkg/label"
	"github.com/dotcloud/docker/pkg/libcontainer/cgroups"
	"github.com/dotcloud/docker/pkg/libcontainer/mount/nodes"
	"github.com/dotcloud/docker/pkg/system"
	"github.com/dotcloud/docker/utils"
)

const DriverName = "lxc"

const nanosecondsInSecond = 1000000000

var (
	cpuCount   = uint64(runtime.NumCPU())
	clockTicks = uint64(system.GetClockTicks())
)

func init() {
	execdriver.RegisterInitFunc(DriverName, func(args *execdriver.InitArgs) error {
		runtime.LockOSThread()
		if err := setupEnv(args); err != nil {
			return err
		}
		if err := setupHostname(args); err != nil {
			return err
		}
		if err := setupNetworking(args); err != nil {
			return err
		}
		if err := setupCapabilities(args); err != nil {
			return err
		}
		if err := setupWorkingDirectory(args); err != nil {
			return err
		}
		if err := system.CloseFdsFrom(3); err != nil {
			return err
		}
		if err := changeUser(args); err != nil {
			return err
		}

		path, err := exec.LookPath(args.Args[0])
		if err != nil {
			log.Printf("Unable to locate %v", args.Args[0])
			os.Exit(127)
		}
		if err := syscall.Exec(path, args.Args, os.Environ()); err != nil {
			return fmt.Errorf("dockerinit unable to execute %s - %s", path, err)
		}
		panic("Unreachable")
	})
}

type driver struct {
	root       string // root path for the driver to use
	apparmor   bool
	sharedRoot bool
}

func NewDriver(root string, apparmor bool) (*driver, error) {
	// setup unconfined symlink
	if err := linkLxcStart(root); err != nil {
		return nil, err
	}
	return &driver{
		apparmor:   apparmor,
		root:       root,
		sharedRoot: rootIsShared(),
	}, nil
}

func (d *driver) Name() string {
	version := d.version()
	return fmt.Sprintf("%s-%s", DriverName, version)
}

func (d *driver) Run(c *execdriver.Command, pipes *execdriver.Pipes, startCallback execdriver.StartCallback) (int, error) {
	if err := execdriver.SetTerminal(c, pipes); err != nil {
		return -1, err
	}
	if err := d.generateEnvConfig(c); err != nil {
		return -1, err
	}
	configPath, err := d.generateLXCConfig(c)
	if err != nil {
		return -1, err
	}
	params := []string{
		"lxc-start",
		"-n", c.ID,
		"-f", configPath,
		"--",
		c.InitPath,
		"-driver",
		DriverName,
	}

	if c.Network.Interface != nil {
		params = append(params,
			"-g", c.Network.Interface.Gateway,
			"-i", fmt.Sprintf("%s/%d", c.Network.Interface.IPAddress, c.Network.Interface.IPPrefixLen),
		)
	}
	params = append(params,
		"-mtu", strconv.Itoa(c.Network.Mtu),
	)

	if c.User != "" {
		params = append(params, "-u", c.User)
	}

	if c.Privileged {
		if d.apparmor {
			params[0] = path.Join(d.root, "lxc-start-unconfined")

		}
		params = append(params, "-privileged")
	}

	if c.WorkingDir != "" {
		params = append(params, "-w", c.WorkingDir)
	}

	params = append(params, "--", c.Entrypoint)
	params = append(params, c.Arguments...)

	if d.sharedRoot {
		// lxc-start really needs / to be non-shared, or all kinds of stuff break
		// when lxc-start unmount things and those unmounts propagate to the main
		// mount namespace.
		// What we really want is to clone into a new namespace and then
		// mount / MS_REC|MS_SLAVE, but since we can't really clone or fork
		// without exec in go we have to do this horrible shell hack...
		shellString :=
			"mount --make-rslave /; exec " +
				utils.ShellQuoteArguments(params)

		params = []string{
			"unshare", "-m", "--", "/bin/sh", "-c", shellString,
		}
	}

	var (
		name = params[0]
		arg  = params[1:]
	)
	aname, err := exec.LookPath(name)
	if err != nil {
		aname = name
	}
	c.Path = aname
	c.Args = append([]string{name}, arg...)

	if err := nodes.CreateDeviceNodes(c.Rootfs, c.AutoCreatedDevices); err != nil {
		return -1, err
	}

	if err := c.Start(); err != nil {
		return -1, err
	}

	var (
		waitErr  error
		waitLock = make(chan struct{})
	)

	go func() {
		if err := c.Wait(); err != nil {
			if _, ok := err.(*exec.ExitError); !ok { // Do not propagate the error if it's simply a status code != 0
				waitErr = err
			}
		}
		close(waitLock)
	}()

	// Poll lxc for RUNNING status
	pid, err := d.waitForStart(c, waitLock)
	if err != nil {
		if c.Process != nil {
			c.Process.Kill()
			c.Wait()
		}
		return -1, err
	}

	c.ContainerPid = pid

	if startCallback != nil {
		startCallback(c)
	}

	<-waitLock

	return getExitCode(c), waitErr
}

/// Return the exit code of the process
// if the process has not exited -1 will be returned
func getExitCode(c *execdriver.Command) int {
	if c.ProcessState == nil {
		return -1
	}
	return c.ProcessState.Sys().(syscall.WaitStatus).ExitStatus()
}

func (d *driver) Kill(c *execdriver.Command, sig int) error {
	return KillLxc(c.ID, sig)
}

func (d *driver) Pause(c *execdriver.Command) error {
	_, err := exec.LookPath("lxc-freeze")
	if err == nil {
		output, errExec := exec.Command("lxc-freeze", "-n", c.ID).CombinedOutput()
		if errExec != nil {
			return fmt.Errorf("Err: %s Output: %s", errExec, output)
		}
	}

	return err
}

func (d *driver) Unpause(c *execdriver.Command) error {
	_, err := exec.LookPath("lxc-unfreeze")
	if err == nil {
		output, errExec := exec.Command("lxc-unfreeze", "-n", c.ID).CombinedOutput()
		if errExec != nil {
			return fmt.Errorf("Err: %s Output: %s", errExec, output)
		}
	}

	return err
}

func (d *driver) Terminate(c *execdriver.Command) error {
	return KillLxc(c.ID, 9)
}

func (d *driver) version() string {
	var (
		version string
		output  []byte
		err     error
	)
	if _, errPath := exec.LookPath("lxc-version"); errPath == nil {
		output, err = exec.Command("lxc-version").CombinedOutput()
	} else {
		output, err = exec.Command("lxc-start", "--version").CombinedOutput()
	}
	if err == nil {
		version = strings.TrimSpace(strings.Trim(string(output), "\n"))
		if parts := strings.SplitN(version, ":", 2); len(parts) == 2 {
			version = strings.TrimSpace(parts[1])
		}
	}
	return version
}

func KillLxc(id string, sig int) error {
	var (
		err    error
		output []byte
	)
	_, err = exec.LookPath("lxc-kill")
	if err == nil {
		output, err = exec.Command("lxc-kill", "-n", id, strconv.Itoa(sig)).CombinedOutput()
	} else {
		output, err = exec.Command("lxc-stop", "-k", "-n", id, strconv.Itoa(sig)).CombinedOutput()
	}
	if err != nil {
		return fmt.Errorf("Err: %s Output: %s", err, output)
	}
	return nil
}

// wait for the process to start and return the pid for the process
func (d *driver) waitForStart(c *execdriver.Command, waitLock chan struct{}) (int, error) {
	var (
		err    error
		output []byte
	)
	// We wait for the container to be fully running.
	// Timeout after 5 seconds. In case of broken pipe, just retry.
	// Note: The container can run and finish correctly before
	// the end of this loop
	for now := time.Now(); time.Since(now) < 5*time.Second; {
		select {
		case <-waitLock:
			// If the process dies while waiting for it, just return
			return -1, nil
		default:
		}

		output, err = d.getInfo(c.ID)
		if err == nil {
			info, err := parseLxcInfo(strings.Trim(string(output), "\n"))
			if err != nil {
				return -1, err
			}
			if info.Running {
				return info.Pid, nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return -1, execdriver.ErrNotRunning
}

func (d *driver) getInfo(id string) ([]byte, error) {
	return exec.Command("lxc-info", "-n", id).CombinedOutput()
}

type info struct {
	ID     string
	driver *driver
}

func (i *info) IsRunning() bool {
	var running bool

	output, err := i.driver.getInfo(i.ID)
	if err != nil {
		utils.Errorf("Error getting info for lxc container %s: %s (%s)", i.ID, err, output)
		return false
	}
	if strings.Contains(strings.Trim(string(output), "\n"), "RUNNING") {
		running = true
	}
	return running
}

func (d *driver) Info(id string) execdriver.Info {
	return &info{
		ID:     id,
		driver: d,
	}
}

func (d *driver) GetPidsForContainer(id string) ([]int, error) {
	pids := []int{}

	// cpu is chosen because it is the only non optional subsystem in cgroups
	subsystem := "cpu"
	cgroupRoot, err := cgroups.FindCgroupMountpoint(subsystem)
	if err != nil {
		return pids, err
	}

	cgroupDir, err := cgroups.GetThisCgroupDir(subsystem)
	if err != nil {
		return pids, err
	}

	filename := filepath.Join(cgroupRoot, cgroupDir, id, "tasks")
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		// With more recent lxc versions use, cgroup will be in lxc/
		filename = filepath.Join(cgroupRoot, cgroupDir, "lxc", id, "tasks")
	}

	output, err := ioutil.ReadFile(filename)
	if err != nil {
		return pids, err
	}
	for _, p := range strings.Split(strings.Trim(string(output), "\n"), "\n") {
		if len(p) == 0 {
			continue
		}
		pid, err := strconv.Atoi(p)
		if err != nil {
			return pids, fmt.Errorf("Invalid pid '%s': %s", p, err)
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

func linkLxcStart(root string) error {
	sourcePath, err := exec.LookPath("lxc-start")
	if err != nil {
		return err
	}
	targetPath := path.Join(root, "lxc-start-unconfined")

	if _, err := os.Lstat(targetPath); err != nil && !os.IsNotExist(err) {
		return err
	} else if err == nil {
		if err := os.Remove(targetPath); err != nil {
			return err
		}
	}
	return os.Symlink(sourcePath, targetPath)
}

// TODO: This can be moved to the mountinfo reader in the mount pkg
func rootIsShared() bool {
	if data, err := ioutil.ReadFile("/proc/self/mountinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			cols := strings.Split(line, " ")
			if len(cols) >= 6 && cols[4] == "/" {
				return strings.HasPrefix(cols[6], "shared")
			}
		}
	}

	// No idea, probably safe to assume so
	return true
}

func (d *driver) generateLXCConfig(c *execdriver.Command) (string, error) {
	var (
		process, mount string
		root           = path.Join(d.root, "containers", c.ID, "config.lxc")
		labels         = c.Config["label"]
	)
	fo, err := os.Create(root)
	if err != nil {
		return "", err
	}
	defer fo.Close()

	if len(labels) > 0 {
		process, mount, err = label.GenLabels(labels[0])
		if err != nil {
			return "", err
		}
	}

	if err := LxcTemplateCompiled.Execute(fo, struct {
		*execdriver.Command
		AppArmor     bool
		ProcessLabel string
		MountLabel   string
	}{
		Command:      c,
		AppArmor:     d.apparmor,
		ProcessLabel: process,
		MountLabel:   mount,
	}); err != nil {
		return "", err
	}
	return root, nil
}

func (d *driver) generateEnvConfig(c *execdriver.Command) error {
	data, err := json.Marshal(c.Env)
	if err != nil {
		return err
	}
	p := path.Join(d.root, "containers", c.ID, "config.env")
	c.Mounts = append(c.Mounts, execdriver.Mount{p, "/.dockerenv", false, true})

	return ioutil.WriteFile(p, data, 0600)
}

func (d *driver) Stats(c *execdriver.Command) (*cgroups.Stats, error) {
	_, err := exec.LookPath("lxc-cgroup")

	if err != nil {
		return nil, err
  }

  stats := cgroups.NewStats()

  err = getCpuStats(c, stats)
  if err != nil {
    return nil, err
  }

  err = getCpuAcctStats(c, stats)
  if err != nil {
    return nil, err
  }

  err = getMemoryStats(c, stats)
  if err != nil {
    return nil, err
  }

  err = getBlkioStats(c, stats)
  if err != nil {
    return nil, err
  }

  return stats, nil
}

func getCpuStats(c *execdriver.Command, stats *cgroups.Stats) error {
	output, errExec := exec.Command("lxc-cgroup", "-n", c.ID, "cpu.stat").CombinedOutput()
	if errExec != nil {
    return fmt.Errorf("Err: %s Output: %s", errExec, output)
	}

	sc := bufio.NewScanner(bytes.NewReader(output))
	for sc.Scan() {
		t, v, err := cgroups.GetCgroupParamKeyValue(sc.Text())
		if err != nil {
			return err
		}
		switch t {
		case "nr_periods":
			stats.CpuStats.ThrottlingData.Periods = v

		case "nr_throttled":
			stats.CpuStats.ThrottlingData.ThrottledPeriods = v

		case "throttled_time":
			stats.CpuStats.ThrottlingData.ThrottledTime = v
		}
	}

  return nil
}

func getCpuAcctStats(c *execdriver.Command, stats *cgroups.Stats) error {
	var (
		startCpu, lastCpu, startSystem, lastSystem, startUsage, lastUsage, kernelModeUsage, userModeUsage, percentage uint64
    err error
    output []byte
	)

	output, err = exec.Command("lxc-cgroup", "-n", c.ID, "cpuacct.stat").CombinedOutput()
	if err != nil {
    return fmt.Errorf("Err: %s Output: %s", err, output)
	}
	if kernelModeUsage, userModeUsage, err = cgroups.GetCpuUsage(strings.Trim(string(output), "\n")); err != nil {
		return err
	}
	startCpu = kernelModeUsage + userModeUsage
	if startSystem, err = cgroups.GetSystemCpuUsage(); err != nil {
		return err
	}
	startUsageTime := time.Now()
	output, err = exec.Command("lxc-cgroup", "-n", c.ID, "cpuacct.usage").CombinedOutput()
	if err != nil {
    return fmt.Errorf("Err: %s Output: %s", err, output)
	}
	if startUsage, err = strconv.ParseUint(strings.Trim(string(output), "\n"), 10, 64); err != nil {
		return err
	}

	// sample for 100ms
	time.Sleep(100 * time.Millisecond)

	output, err = exec.Command("lxc-cgroup", "-n", c.ID, "cpuacct.stat").CombinedOutput()
	if err != nil {
    return fmt.Errorf("Err: %s Output: %s", err, output)
	}
	if kernelModeUsage, userModeUsage, err = cgroups.GetCpuUsage(strings.Trim(string(output), "\n")); err != nil {
		return err
	}
	lastCpu = kernelModeUsage + userModeUsage
	if lastSystem, err = cgroups.GetSystemCpuUsage(); err != nil {
		return err
	}
	usageSampleDuration := time.Since(startUsageTime)
	output, err = exec.Command("lxc-cgroup", "-n", c.ID, "cpuacct.usage").CombinedOutput()
	if err != nil {
    return fmt.Errorf("Err: %s Output: %s", err, output)
	}
	if lastUsage, err = strconv.ParseUint(strings.Trim(string(output), "\n"), 10, 64); err != nil {
		return err
	}

	var (
		deltaProc   = lastCpu - startCpu
		deltaSystem = lastSystem - startSystem
		deltaUsage  = lastUsage - startUsage
	)
	if deltaSystem > 0.0 {
		percentage = ((deltaProc / deltaSystem) * clockTicks) * cpuCount
	}
	// NOTE: a percentage over 100% is valid for POSIX because that means the
	// processes is using multiple cores
	stats.CpuStats.CpuUsage.PercentUsage = percentage
	// Delta usage is in nanoseconds of CPU time so get the usage (in cores) over the sample time.
	stats.CpuStats.CpuUsage.CurrentUsage = deltaUsage / uint64(usageSampleDuration.Nanoseconds())
	output, err = exec.Command("lxc-cgroup", "-n", c.ID, "cpuacct.usage_percpu").CombinedOutput()
	if err != nil {
    return fmt.Errorf("Err: %s Output: %s", err, output)
	}
	percpuUsage, err := cgroups.GetPercpuUsage(strings.Trim(string(output), "\n"))
	if err != nil {
		return err
	}
	stats.CpuStats.CpuUsage.PercpuUsage = percpuUsage
	stats.CpuStats.CpuUsage.UsageInKernelmode = (kernelModeUsage * nanosecondsInSecond) / clockTicks
	stats.CpuStats.CpuUsage.UsageInUsermode = (userModeUsage * nanosecondsInSecond) / clockTicks
	return nil
}

func getMemoryStats(c *execdriver.Command, stats *cgroups.Stats) error {
  var value uint64
  var err error
	output, errExec := exec.Command("lxc-cgroup", "-n", c.ID, "memory.failcnt").CombinedOutput()
	if errExec != nil {
    return fmt.Errorf("Err: %s Output: %s", errExec, output)
	}
  if value, err = strconv.ParseUint(strings.Trim(string(output), "\n"), 10, 64); err != nil {
		return err
	}
	stats.MemoryStats.Failcnt = value

	output, errExec = exec.Command("lxc-cgroup", "-n", c.ID, "memory.max_usage_in_bytes").CombinedOutput()
	if errExec != nil {
    return fmt.Errorf("Err: %s Output: %s", errExec, output)
	}
  if value, err = strconv.ParseUint(strings.Trim(string(output), "\n"), 10, 64); err != nil {
		return err
	}
	stats.MemoryStats.MaxUsage = value

	output, errExec = exec.Command("lxc-cgroup", "-n", c.ID, "memory.usage_in_bytes").CombinedOutput()
	if errExec != nil {
    return fmt.Errorf("Err: %s Output: %s", errExec, output)
	}
  if value, err = strconv.ParseUint(strings.Trim(string(output), "\n"), 10, 64); err != nil {
		return err
	}
	stats.MemoryStats.Usage = value

	output, errExec = exec.Command("lxc-cgroup", "-n", c.ID, "memory.stat").CombinedOutput()
	sc := bufio.NewScanner(bytes.NewReader(output))
	for sc.Scan() {
		t, v, err := cgroups.GetCgroupParamKeyValue(sc.Text())
		if err != nil {
			return err
		}
		stats.MemoryStats.Stats[t] = v
	}

  return nil
}

func getBlkioStats(c *execdriver.Command, stats *cgroups.Stats) error {
	var blkioStats []cgroups.BlkioStatEntry
	var err error

	output, errExec := exec.Command("lxc-cgroup", "-n", c.ID, "blkio.sectors_recursive").CombinedOutput()
	if errExec == nil {
	  sc := bufio.NewScanner(bytes.NewReader(output))
    if blkioStats, err = cgroups.GetBlkioStat(sc); err != nil {
		  return err
	  }
	  stats.BlkioStats.SectorsRecursive = blkioStats
	}

	output, errExec = exec.Command("lxc-cgroup", "-n", c.ID, "blkio.io_service_bytes_recursive").CombinedOutput()
	if errExec == nil {
    sc := bufio.NewScanner(bytes.NewReader(output))
	  if blkioStats, err = cgroups.GetBlkioStat(sc); err != nil {
		  return err
	  }
	  stats.BlkioStats.IoServiceBytesRecursive = blkioStats
	}

	output, errExec = exec.Command("lxc-cgroup", "-n", c.ID, "blkio.io_serviced_recursive").CombinedOutput()
	if errExec == nil {
    sc := bufio.NewScanner(bytes.NewReader(output))
	  if blkioStats, err = cgroups.GetBlkioStat(sc); err != nil {
		  return err
	  }
	  stats.BlkioStats.IoServicedRecursive = blkioStats
	}

	output, errExec = exec.Command("lxc-cgroup", "-n", c.ID, "blkio.io_queued_recursive").CombinedOutput()
	if errExec == nil {
    sc := bufio.NewScanner(bytes.NewReader(output))
	  if blkioStats, err = cgroups.GetBlkioStat(sc); err != nil {
		  return err
	  }
	  stats.BlkioStats.IoQueuedRecursive = blkioStats
	}

  return nil
}
