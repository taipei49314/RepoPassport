//go:build windows

package sourcequalification

import (
	"context"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const gateWindowsTerminateExitCode = 0xc000013a

type windowsGateWaitResult struct {
	err      error
	exitCode *int64
}

type windowsJobBasicAccounting struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

func executeOSGateProcess(ctx context.Context, request gateProcessRequest) (gateProcessResult, error) {
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		return gateProcessResult{Blocked: true}, errGateProcessBlocked
	}
	defer stdin.Close()
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return gateProcessResult{Blocked: true}, errGateProcessBlocked
	}
	defer stdoutReader.Close()
	defer stdoutWriter.Close()
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		return gateProcessResult{Blocked: true}, errGateProcessBlocked
	}
	defer stderrReader.Close()
	defer stderrWriter.Close()

	childHandles := []windows.Handle{
		windows.Handle(stdin.Fd()),
		windows.Handle(stdoutWriter.Fd()),
		windows.Handle(stderrWriter.Fd()),
	}
	for _, handle := range childHandles {
		if err := windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return gateProcessResult{Blocked: true}, errGateProcessBlocked
		}
	}
	for _, reader := range []*os.File{stdoutReader, stderrReader} {
		if err := windows.SetHandleInformation(windows.Handle(reader.Fd()), windows.HANDLE_FLAG_INHERIT, 0); err != nil {
			return gateProcessResult{Blocked: true}, errGateProcessBlocked
		}
	}

	attributeList, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return gateProcessResult{Blocked: true}, errGateProcessBlocked
	}
	defer attributeList.Delete()
	if err := attributeList.Update(
		windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&childHandles[0]),
		uintptr(len(childHandles))*unsafe.Sizeof(childHandles[0]),
	); err != nil {
		return gateProcessResult{Blocked: true}, errGateProcessBlocked
	}

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return gateProcessResult{Blocked: true}, errGateProcessBlocked
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)),
		uint32(unsafe.Sizeof(limits)),
	); err != nil {
		return gateProcessResult{Blocked: true}, errGateProcessBlocked
	}

	application, err := windows.UTF16PtrFromString(request.Application)
	if err != nil {
		return gateProcessResult{}, errGateProcessInvalid
	}
	commandLine, err := windows.UTF16FromString(windows.ComposeCommandLine(append([]string{request.Application}, request.Args...)))
	if err != nil {
		return gateProcessResult{}, errGateProcessInvalid
	}
	directory, err := windows.UTF16PtrFromString(request.Dir)
	if err != nil {
		return gateProcessResult{}, errGateProcessInvalid
	}
	environment := windowsGateEnvironmentBlock(request.Env)
	startup := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb:        uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
			Flags:     windows.STARTF_USESTDHANDLES,
			StdInput:  childHandles[0],
			StdOutput: childHandles[1],
			StdErr:    childHandles[2],
		},
		ProcThreadAttributeList: attributeList.List(),
	}
	process := windows.ProcessInformation{}
	creationFlags := uint32(
		windows.CREATE_SUSPENDED |
			windows.CREATE_NEW_PROCESS_GROUP |
			windows.CREATE_DEFAULT_ERROR_MODE |
			windows.CREATE_UNICODE_ENVIRONMENT |
			windows.EXTENDED_STARTUPINFO_PRESENT,
	)
	if err := windows.CreateProcess(
		application,
		&commandLine[0],
		nil,
		nil,
		true,
		creationFlags,
		&environment[0],
		directory,
		&startup.StartupInfo,
		&process,
	); err != nil {
		return gateProcessResult{Blocked: true}, errGateProcessBlocked
	}
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	_ = stdin.Close()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()

	stdout := newGateOutputCapture(request.StdoutLimit)
	stderr := newGateOutputCapture(request.StderrLimit)
	stdoutDone := drainWindowsGatePipe(stdoutReader, stdout)
	stderrDone := drainWindowsGatePipe(stderrReader, stderr)

	if err := windows.AssignProcessToJobObject(job, process.Process); err != nil {
		cleanupFailed := windows.TerminateProcess(process.Process, gateWindowsTerminateExitCode) != nil
		if event, waitErr := windows.WaitForSingleObject(process.Process, uint32(gateProcessCleanupTimeout/time.Millisecond)); waitErr != nil || event != windows.WAIT_OBJECT_0 {
			cleanupFailed = true
		}
		return gateProcessResult{Blocked: true, CleanupFailed: cleanupFailed}, errGateProcessBlocked
	}
	if _, err := windows.ResumeThread(process.Thread); err != nil {
		cleanupFailed := windows.TerminateJobObject(job, gateWindowsTerminateExitCode) != nil
		if event, waitErr := windows.WaitForSingleObject(process.Process, uint32(gateProcessCleanupTimeout/time.Millisecond)); waitErr != nil || event != windows.WAIT_OBJECT_0 {
			cleanupFailed = true
		}
		return gateProcessResult{Blocked: true, CleanupFailed: cleanupFailed}, errGateProcessBlocked
	}

	waitDone := make(chan windowsGateWaitResult, 1)
	go func() {
		event, waitErr := windows.WaitForSingleObject(process.Process, windows.INFINITE)
		if waitErr == nil && event != windows.WAIT_OBJECT_0 {
			waitErr = errGateProcessBlocked
		}
		var exitCode *int64
		if waitErr == nil {
			var raw uint32
			if waitErr = windows.GetExitCodeProcess(process.Process, &raw); waitErr == nil {
				value := int64(int32(raw))
				exitCode = &value
			}
		}
		waitDone <- windowsGateWaitResult{err: waitErr, exitCode: exitCode}
	}()

	result := gateProcessResult{}
	timeout := time.NewTimer(request.Timeout)
	defer timeout.Stop()
	var waitResult windowsGateWaitResult
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

	terminate := result.TimedOut || result.Cancelled
	if !terminate && rootFinished {
		active, queryErr := windowsGateActiveProcesses(job)
		if queryErr != nil {
			result.CleanupFailed = true
		} else if active != 0 {
			terminate = true
			result.CleanupFailed = true
		}
	}
	if terminate {
		if err := windows.TerminateJobObject(job, gateWindowsTerminateExitCode); err != nil {
			result.CleanupFailed = true
		}
	}

	cleanupDeadline := time.Now().Add(gateProcessCleanupTimeout)
	if !rootFinished {
		var ok bool
		waitResult, ok = waitWindowsGateResult(waitDone, cleanupDeadline)
		if !ok {
			result.CleanupFailed = true
		} else {
			rootFinished = true
		}
	}
	if !waitWindowsGateJob(job, cleanupDeadline) {
		result.CleanupFailed = true
	}

	stdoutErr, stdoutComplete := waitWindowsGatePipe(stdoutDone, cleanupDeadline)
	stderrErr, stderrComplete := waitWindowsGatePipe(stderrDone, cleanupDeadline)
	if !stdoutComplete || !stderrComplete {
		result.CleanupFailed = true
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
	}
	if stdoutErr != nil || stderrErr != nil || waitResult.err != nil {
		result.CleanupFailed = true
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

func windowsGateEnvironmentBlock(environment []string) []uint16 {
	ordered := append([]string(nil), environment...)
	sort.Slice(ordered, func(left, right int) bool {
		return strings.ToUpper(ordered[left]) < strings.ToUpper(ordered[right])
	})
	block := strings.Join(ordered, "\x00") + "\x00\x00"
	return utf16.Encode([]rune(block))
}

func drainWindowsGatePipe(reader *os.File, destination io.Writer) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(destination, reader)
		done <- err
	}()
	return done
}

func windowsGateActiveProcesses(job windows.Handle) (uint32, error) {
	accounting := windowsJobBasicAccounting{}
	if err := windows.QueryInformationJobObject(
		job,
		windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&accounting)),
		uint32(unsafe.Sizeof(accounting)),
		nil,
	); err != nil {
		return 0, err
	}
	return accounting.ActiveProcesses, nil
}

func waitWindowsGateJob(job windows.Handle, deadline time.Time) bool {
	for {
		active, err := windowsGateActiveProcesses(job)
		if err != nil {
			return false
		}
		if active == 0 {
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

func waitWindowsGateResult(channel <-chan windowsGateWaitResult, deadline time.Time) (windowsGateWaitResult, bool) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return windowsGateWaitResult{}, false
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case result := <-channel:
		return result, true
	case <-timer.C:
		return windowsGateWaitResult{}, false
	}
}

func waitWindowsGatePipe(channel <-chan error, deadline time.Time) (error, bool) {
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
