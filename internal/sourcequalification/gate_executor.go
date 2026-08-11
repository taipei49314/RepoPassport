package sourcequalification

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	maximumGateArguments        = 256
	maximumGateEnvironment      = 128
	maximumGateProcessTextBytes = 64 << 10
	maximumGateProcessTimeout   = time.Hour
	gateProcessCleanupTimeout   = 30 * time.Second
)

var (
	errGateProcessInvalid                = errors.New("gate process request is invalid")
	errGateProcessBlocked                = errors.New("gate process prerequisite is unavailable")
	errGateApplicationBindingUnavailable = errors.New("immutable gate application binding is unavailable")
)

type osGateExecutor struct{}

func newOSGateExecutor() gateExecutor {
	return osGateExecutor{}
}

func (osGateExecutor) BindApplications(
	context.Context,
	map[string]string,
) (gateApplicationBinding, error) {
	// Process-group/job containment does not make the host toolchain immutable.
	// Until a platform implementation can hold and execute fixed executable and
	// dependency identities for the entire lane, production qualification must
	// report BLOCKED rather than accept mutable pathnames as trusted tools.
	return nil, errGateApplicationBindingUnavailable
}

func (osGateExecutor) Execute(ctx context.Context, request gateProcessRequest) (gateProcessResult, error) {
	environment, environmentOK := normalizeGateProcessEnvironment(request.Env)
	request.Env = environment
	if ctx == nil || nilGateDependency(ctx) || !environmentOK || !validGateProcessRequest(request) {
		return gateProcessResult{}, errGateProcessInvalid
	}
	if ctx.Err() != nil {
		return gateProcessResult{Cancelled: true}, nil
	}
	if !availableGateApplication(request.Application) || !validGateProcessDirectory(request.Dir) {
		return gateProcessResult{Blocked: true}, errGateProcessBlocked
	}

	request.Args = append([]string(nil), request.Args...)
	request.Env = append([]string(nil), request.Env...)
	return executeOSGateProcess(ctx, request)
}

func normalizeGateProcessEnvironment(environment []string) ([]string, bool) {
	if len(environment) == 0 || len(environment) > maximumGateEnvironment {
		return nil, false
	}
	result := make([]string, 0, len(environment))
	indexes := make(map[string]int, len(environment))
	total := 0
	for _, item := range environment {
		name, _, found := strings.Cut(item, "=")
		canonicalName := strings.ToUpper(name)
		total += len(item)
		if !found || name == "" || strings.IndexByte(item, 0) >= 0 || strings.ContainsAny(name, "\r\n") ||
			total > maximumGateProcessTextBytes {
			return nil, false
		}
		if index, duplicate := indexes[canonicalName]; duplicate {
			result[index] = item
			continue
		}
		indexes[canonicalName] = len(result)
		result = append(result, item)
	}
	return result, true
}

func validGateProcessRequest(request gateProcessRequest) bool {
	if !cleanAbsoluteGatePath(request.Application) || !cleanAbsoluteGatePath(request.Dir) ||
		!validGateProcessNetwork(request.Network) ||
		request.Timeout <= 0 || request.Timeout > maximumGateProcessTimeout ||
		request.StdoutLimit <= 0 || request.StdoutLimit > maximumGateOutputBytes ||
		request.StderrLimit <= 0 || request.StderrLimit > maximumGateOutputBytes ||
		len(request.Args) > maximumGateArguments || len(request.Env) == 0 ||
		len(request.Env) > maximumGateEnvironment {
		return false
	}

	total := len(request.Application) + len(request.Dir)
	for _, argument := range request.Args {
		if strings.IndexByte(argument, 0) >= 0 {
			return false
		}
		total += len(argument)
	}
	for _, item := range request.Env {
		name, _, found := strings.Cut(item, "=")
		if !found || name == "" || strings.IndexByte(item, 0) >= 0 || strings.ContainsAny(name, "\r\n") {
			return false
		}
		total += len(item)
	}
	return total <= maximumGateProcessTextBytes
}

func validGateProcessNetwork(network NetworkMode) bool {
	switch network {
	case NetworkNone, NetworkGoModules, NetworkVulnerabilityDatabase,
		NetworkGoModulesAndVulnerabilityDatabase:
		return true
	default:
		return false
	}
}

func availableGateApplication(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && filepath.IsAbs(resolved) && sameCanonicalPath(path, resolved)
}

func validGateProcessDirectory(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && filepath.IsAbs(resolved) && sameCanonicalPath(path, resolved)
}

type gateOutputCapture struct {
	limit    int64
	data     []byte
	overflow bool
}

func newGateOutputCapture(limit int64) *gateOutputCapture {
	return &gateOutputCapture{limit: limit}
}

func (capture *gateOutputCapture) Write(value []byte) (int, error) {
	written := len(value)
	remaining := capture.limit - int64(len(capture.data))
	if remaining > 0 {
		retained := int64(len(value))
		if retained > remaining {
			retained = remaining
		}
		capture.data = append(capture.data, value[:int(retained)]...)
	}
	if int64(len(value)) > remaining {
		capture.overflow = true
	}
	return written, nil
}

func (capture *gateOutputCapture) result() ([]byte, bool) {
	return append([]byte(nil), capture.data...), capture.overflow
}

func gateProcessExitCode(value int) *int64 {
	result := int64(value)
	return &result
}
