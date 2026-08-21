//go:build windows

package sourcequalification

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/taipei49314/RepoPassport/internal/pathsecurity"
	"github.com/taipei49314/RepoPassport/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

const (
	windowsAppContainerBootstrapArgv0 = "RepoPass.SourceQualification.Windows.AppContainer"
	windowsAppContainerBootstrapError = 125
)

// RunWindowsAppContainerGateBootstrap handles the private argv[0] used by the
// Windows containment executor. It is not part of the RFC command vocabulary.
func RunWindowsAppContainerGateBootstrap(
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) (int, bool) {
	if len(args) == 0 || args[0] != windowsAppContainerBootstrapArgv0 {
		return 0, false
	}
	appContainer, err := windowssecurity.CurrentProcessIsAppContainer()
	if err != nil || !appContainer {
		return 0, false
	}
	if len(args) < 2 || stdin == nil || stdout == nil || stderr == nil ||
		!validWindowsAppContainerBootstrapApplication(args[1]) {
		return windowsAppContainerBootstrapError, true
	}
	temporary := os.Getenv("GOTMPDIR")
	if !validWindowsAppContainerBootstrapDirectory(temporary) ||
		os.Getenv(pathsecurity.QualificationRootsEnvironment) == "" {
		return windowsAppContainerBootstrapError, true
	}
	for _, name := range []string{"TMP", "TEMP", "TMPDIR"} {
		if err := os.Setenv(name, temporary); err != nil {
			return windowsAppContainerBootstrapError, true
		}
	}

	command := exec.Command(args[1], args[2:]...)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode(), true
		}
		return windowsAppContainerBootstrapError, true
	}
	return 0, true
}

func validWindowsAppContainerBootstrapApplication(path string) bool {
	if !cleanAbsoluteGatePath(path) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		!windowsAppContainerBootstrapReparsePoint(path)
}

func validWindowsAppContainerBootstrapDirectory(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 &&
		!windowsAppContainerBootstrapReparsePoint(path)
}

func windowsAppContainerBootstrapReparsePoint(path string) bool {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attributes, err := windows.GetFileAttributes(pointer)
	return err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
