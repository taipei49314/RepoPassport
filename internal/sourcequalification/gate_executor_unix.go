//go:build linux

package sourcequalification

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type unixGateWaitResult struct {
	err      error
	exitCode *int64
}

func executeOSGateProcess(ctx context.Context, request gateProcessRequest) (gateProcessResult, error) {
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return gateProcessResult{Blocked: true}, errGateProcessBlocked
	}
	defer stdoutReader.Close()
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutWriter.Close()
		return gateProcessResult{Blocked: true}, errGateProcessBlocked
	}
	defer stderrReader.Close()

	isolationApplication, isolationArguments, isolationEnvironment, ok := linuxSelectGateIsolation(
		ctx,
		request.Network,
		request.Env,
		request.Application,
		request.Args,
	)
	if !ok {
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
		return gateProcessResult{Blocked: true}, errors.Join(
			errGateProcessBlocked,
			errGateIsolationUnavailable,
		)
	}
	command := exec.Command(isolationApplication, isolationArguments...)
	command.Dir = request.Dir
	command.Env = append([]string(nil), isolationEnvironment...)
	command.Stdout = stdoutWriter
	command.Stderr = stderrWriter
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
		return gateProcessResult{Blocked: true}, errGateProcessBlocked
	}

	result := gateProcessResult{}
	if err := stdoutWriter.Close(); err != nil {
		result.CleanupFailed = true
	}
	if err := stderrWriter.Close(); err != nil {
		result.CleanupFailed = true
	}

	stdout := newGateOutputCapture(request.StdoutLimit)
	stderr := newGateOutputCapture(request.StderrLimit)
	stdoutDone := drainUnixGatePipe(stdoutReader, stdout)
	stderrDone := drainUnixGatePipe(stderrReader, stderr)
	waitDone := make(chan unixGateWaitResult, 1)
	go func() {
		waitErr := command.Wait()
		var exitCode *int64
		if command.ProcessState != nil {
			exitCode = gateProcessExitCode(command.ProcessState.ExitCode())
		}
		waitDone <- unixGateWaitResult{err: waitErr, exitCode: exitCode}
	}()

	timeout := time.NewTimer(request.Timeout)
	defer timeout.Stop()
	var waitResult unixGateWaitResult
	rootFinished := false
	select {
	case waitResult = <-waitDone:
		rootFinished = true
	case <-ctx.Done():
		result.Cancelled = true
	case <-timeout.C:
		if ctx.Err() != nil {
			result.Cancelled = true
		} else {
			result.TimedOut = true
		}
	}
	if ctx.Err() != nil {
		result.Cancelled = true
	}

	processGroup := command.Process.Pid
	terminated := result.TimedOut || result.Cancelled
	if !terminated && rootFinished {
		alive, checkErr := unixGateProcessGroupAlive(processGroup)
		if checkErr != nil {
			result.CleanupFailed = true
		} else if alive {
			terminated = true
			result.CleanupFailed = true
		}
	}
	if terminated {
		if err := syscall.Kill(-processGroup, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			result.CleanupFailed = true
		}
	}

	cleanupDeadline := time.Now().Add(gateProcessCleanupTimeout)
	if !rootFinished {
		var ok bool
		waitResult, ok = waitUnixGateResult(waitDone, cleanupDeadline)
		if !ok {
			result.CleanupFailed = true
		} else {
			rootFinished = true
		}
	}
	if !waitUnixGateProcessGroup(processGroup, cleanupDeadline) {
		result.CleanupFailed = true
	}

	stdoutErr, stdoutComplete := waitUnixGatePipe(stdoutDone, cleanupDeadline)
	stderrErr, stderrComplete := waitUnixGatePipe(stderrDone, cleanupDeadline)
	if !stdoutComplete || !stderrComplete {
		result.CleanupFailed = true
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
	}
	if stdoutErr != nil || stderrErr != nil {
		result.CleanupFailed = true
	}
	if waitResult.err != nil {
		var exitError *exec.ExitError
		if !errors.As(waitResult.err, &exitError) {
			result.CleanupFailed = true
		}
	}

	if stdoutComplete {
		result.Stdout, result.StdoutOverflow = stdout.result()
	}
	if stderrComplete {
		result.Stderr, result.StderrOverflow = stderr.result()
	}
	if !result.TimedOut && !result.Cancelled && !result.CleanupFailed && rootFinished {
		result.ExitCode = waitResult.exitCode
	}
	return result, nil
}

func linuxSelectGateIsolation(
	ctx context.Context,
	network NetworkMode,
	environment []string,
	application string,
	arguments []string,
) (string, []string, []string, bool) {
	if linuxInNonHostPidNamespace() {
		return "", nil, nil, false
	}
	probeApplication, probeOK := trustedLinuxSystemApplication("/usr/bin/true")
	if !probeOK {
		return "", nil, nil, false
	}
	unshare, unshareOK := trustedLinuxSystemApplication("/usr/bin/unshare")
	if unshareOK {
		rootlessProbe, probeOK := linuxRootlessGateIsolationArguments(network, probeApplication, nil)
		if probeOK && linuxIsolationProbe(ctx, unshare, rootlessProbe, linuxRootlessProbeEnvironment()) {
			rootlessArguments, argsOK := linuxRootlessGateIsolationArguments(network, application, arguments)
			if argsOK {
				return unshare, rootlessArguments, append([]string(nil), environment...), true
			}
		}
	}
	sudo, privilegedArguments, ok := linuxPrivilegedGateIsolationCommand(
		network,
		os.Getuid(),
		os.Getgid(),
		linuxPrivilegedProbeEnvironment(),
		probeApplication,
		nil,
	)
	if !ok || !linuxIsolationProbe(ctx, sudo, privilegedArguments, linuxPrivilegedLauncherEnvironment()) {
		return "", nil, nil, false
	}
	sudo, privilegedArguments, ok = linuxPrivilegedGateIsolationCommand(
		network,
		os.Getuid(),
		os.Getgid(),
		environment,
		application,
		arguments,
	)
	if !ok {
		return "", nil, nil, false
	}
	return sudo, privilegedArguments, linuxPrivilegedLauncherEnvironment(), true
}

func linuxRootlessGateIsolationArguments(network NetworkMode, application string, arguments []string) ([]string, bool) {
	result := []string{
		"--user",
		"--map-root-user",
		"--pid",
		"--fork",
		"--kill-child=KILL",
		"--mount-proc",
	}
	if network == NetworkNone {
		result = append(result, "--net")
	}
	result = append(result, "--")
	if network == NetworkNone {
		wrapped, ok := linuxLoopbackThenExec(application, arguments)
		if !ok {
			return nil, false
		}
		return append(result, wrapped...), true
	}
	if application == "" {
		return nil, false
	}
	result = append(result, application)
	return append(result, arguments...), true
}

func linuxPrivilegedGateIsolationCommand(
	network NetworkMode,
	uid, gid int,
	environment []string,
	application string,
	arguments []string,
) (string, []string, bool) {
	if uid < 0 || gid < 0 || application == "" {
		return "", nil, false
	}
	sudo, sudoOK := trustedLinuxSystemApplication("/usr/bin/sudo")
	unshare, unshareOK := trustedLinuxSystemApplication("/usr/bin/unshare")
	setpriv, setprivOK := trustedLinuxSystemApplication("/usr/bin/setpriv")
	env, envOK := trustedLinuxSystemApplication("/usr/bin/env")
	if !sudoOK || !unshareOK || !setprivOK || !envOK {
		return "", nil, false
	}
	result := []string{"-n", "--", unshare, "--pid", "--fork", "--kill-child=KILL", "--mount-proc"}
	if network == NetworkNone {
		result = append(result, "--net")
	}
	inner := []string{
		setpriv,
		"--reuid=" + strconv.Itoa(uid),
		"--regid=" + strconv.Itoa(gid),
		"--clear-groups",
		"--inh-caps=-all",
		"--ambient-caps=-all",
		"--bounding-set=-all",
		"--no-new-privs",
		"--",
		env,
		"-i",
		"--",
	}
	inner = append(inner, environment...)
	inner = append(inner, application)
	inner = append(inner, arguments...)
	result = append(result, "--")
	if network == NetworkNone {
		wrapped, ok := linuxLoopbackThenExec(inner[0], inner[1:])
		if !ok {
			return "", nil, false
		}
		return sudo, append(result, wrapped...), true
	}
	return sudo, append(result, inner...), true
}

func linuxLoopbackThenExec(application string, arguments []string) ([]string, bool) {
	if application == "" {
		return nil, false
	}
	bash, ip, ok := linuxTrustedLoopbackHelper()
	if !ok {
		return nil, false
	}
	// unshare --net starts with no interfaces. Docker --network none still has
	// loopback; localhost tests and httptest need it. This does not add a route.
	script := ip + ` link set lo up && exec "$@"`
	result := []string{bash, "-c", script, "repopass-netns-lo", application}
	return append(result, arguments...), true
}

func linuxTrustedLoopbackHelper() (bash, ip string, ok bool) {
	for _, candidate := range []string{"/usr/bin/bash", "/bin/bash"} {
		if resolved, trusted := trustedLinuxSystemApplication(candidate); trusted && safeLinuxIsolationExecutable(resolved) {
			bash = resolved
			break
		}
	}
	for _, candidate := range []string{"/usr/sbin/ip", "/usr/bin/ip", "/bin/ip"} {
		if resolved, trusted := trustedLinuxSystemApplication(candidate); trusted && safeLinuxIsolationExecutable(resolved) {
			ip = resolved
			break
		}
	}
	return bash, ip, bash != "" && ip != ""
}

func safeLinuxIsolationExecutable(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for _, current := range path {
		if current == '/' || current == '-' || current == '_' || current == '.' ||
			current >= '0' && current <= '9' ||
			current >= 'A' && current <= 'Z' ||
			current >= 'a' && current <= 'z' {
			continue
		}
		return false
	}
	return true
}

func trustedLinuxSystemApplication(application string) (string, bool) {
	for current := application; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return "", false
		}
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || metadata.Uid != 0 {
			return "", false
		}
		if current == application && !info.Mode().IsRegular() {
			return "", false
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return application, true
}

func linuxInNonHostPidNamespace() bool {
	// Nested unshare --pid from an existing pid namespace leaks the inner
	// init onto the host when the outer pid-namespace init exits. Isolation
	// selection therefore refuses to launch another unshare from inside one.
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return true
	}
	return linuxStatusNSpidCount(status) != 1
}

func linuxIsolationProbe(ctx context.Context, application string, arguments, environment []string) bool {
	if application == "" || len(arguments) == 0 || len(environment) == 0 {
		return false
	}
	probeContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(probeContext, application, arguments...)
	command.Dir = "/"
	command.Env = append([]string(nil), environment...)
	return command.Run() == nil && probeContext.Err() == nil
}

func linuxRootlessProbeEnvironment() []string {
	return []string{"HOME=/", "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "TZ=UTC"}
}

func linuxPrivilegedProbeEnvironment() []string {
	return linuxRootlessProbeEnvironment()
}

func linuxPrivilegedLauncherEnvironment() []string {
	return []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "TZ=UTC"}
}

func drainUnixGatePipe(reader *os.File, destination io.Writer) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(destination, reader)
		done <- err
	}()
	return done
}

func unixGateProcessGroupAlive(processGroup int) (bool, error) {
	err := syscall.Kill(-processGroup, 0)
	switch {
	case err == nil, errors.Is(err, syscall.EPERM):
		return true, nil
	case errors.Is(err, syscall.ESRCH):
		return false, nil
	default:
		return false, err
	}
}

func waitUnixGateProcessGroup(processGroup int, deadline time.Time) bool {
	for {
		alive, err := unixGateProcessGroupAlive(processGroup)
		if err != nil {
			return false
		}
		if !alive {
			return true
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		if remaining > 10*time.Millisecond {
			remaining = 10 * time.Millisecond
		}
		time.Sleep(remaining)
	}
}

func waitUnixGateResult(channel <-chan unixGateWaitResult, deadline time.Time) (unixGateWaitResult, bool) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return unixGateWaitResult{}, false
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case result := <-channel:
		return result, true
	case <-timer.C:
		return unixGateWaitResult{}, false
	}
}

func waitUnixGatePipe(channel <-chan error, deadline time.Time) (error, bool) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, false
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case err := <-channel:
		return err, true
	case <-timer.C:
		return nil, false
	}
}
