//go:build windows

package sourcequalification

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/taipei49314/RepoPassport/internal/qualificationfixture"
)

const (
	windowsReleaseQualificationFixturePrefix    = "release-fixture-"
	windowsReleaseQualificationFixtureFileCount = 6
)

var errWindowsReleaseQualificationFixture = errors.New(
	"Windows release-qualification fixture binding failed",
)

var errWindowsReleaseQualificationFixtureCleanup = errors.New(
	"Windows release-qualification fixture cleanup failed",
)

type windowsReleaseQualificationFixtureBinding struct {
	root           string
	manifestDigest string
	files          gateApplicationBinding
	cleanup        func() error
	released       bool
}

func windowsReleaseQualificationFixtureEnvironmentReserved(environment []string) bool {
	for _, name := range []string{
		qualificationfixture.ImportRootEnv,
		qualificationfixture.ManifestDigestEnv,
	} {
		if windowsEnvironmentContainsKey(environment, name) {
			return true
		}
	}
	return false
}

func windowsReleaseQualificationFixtureTarget(request gateProcessRequest) bool {
	want := []string{"test", "-count=1", "-timeout=30m", "./..."}
	if request.Network != NetworkNone || request.ContainmentApplication == "" ||
		!strings.EqualFold(filepath.Base(request.Application), "go.exe") ||
		len(request.Args) != len(want) {
		return false
	}
	for index := range want {
		if request.Args[index] != want[index] {
			return false
		}
	}
	return true
}

func prepareWindowsReleaseQualificationFixture(
	ctx context.Context,
	request *gateProcessRequest,
) (bindingResult *windowsReleaseQualificationFixtureBinding, resultErr error) {
	if ctx == nil || nilGateDependency(ctx) || ctx.Err() != nil || request == nil ||
		!windowsReleaseQualificationFixtureTarget(*request) ||
		windowsReleaseQualificationFixtureEnvironmentReserved(request.Env) {
		return nil, errWindowsReleaseQualificationFixture
	}
	privateRoot := windowsQualificationPrivateRoot(request.Env)
	if privateRoot == "" {
		return nil, errWindowsReleaseQualificationFixture
	}
	root, cleanup, _, err := createPrivateQualificationStaging(
		privateRoot,
		windowsReleaseQualificationFixturePrefix,
	)
	if err != nil || cleanup == nil {
		return nil, errors.Join(errWindowsReleaseQualificationFixture, err)
	}
	failed := true
	defer func() {
		if failed {
			if cleanupErr := cleanup(); cleanupErr != nil {
				resultErr = errors.Join(
					resultErr,
					errWindowsReleaseQualificationFixtureCleanup,
					cleanupErr,
				)
			}
		}
	}()

	gitPath, err := resolveTrustedGitExecutable(request.Dir)
	if err != nil {
		return nil, errors.Join(errWindowsReleaseQualificationFixture, err)
	}
	hostPath := windowsReleaseQualificationHostPath(
		request.Application,
		gitPath,
		windowsEnvironmentLookup(request.Env, "SYSTEMROOT"),
	)
	if hostPath == "" {
		return nil, errWindowsReleaseQualificationFixture
	}
	hostEnvironment, ok := windowsGateEnvironmentWithReplacements(request.Env, map[string]string{
		"PATH":                hostPath,
		"PATHEXT":             ".EXE",
		"GOFLAGS":             "-buildvcs=false",
		"GOWORK":              "off",
		"GOTOOLCHAIN":         "local",
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_CONFIG_GLOBAL":   "NUL",
		"GIT_TERMINAL_PROMPT": "0",
	})
	if !ok {
		return nil, errWindowsReleaseQualificationFixture
	}
	hostToolBinding, err := newOSGateApplicationBinding(ctx, map[string]string{
		"go":  request.Application,
		"git": gitPath,
	})
	if err != nil || hostToolBinding == nil || nilGateDependency(hostToolBinding) {
		return nil, errors.Join(errWindowsReleaseQualificationFixture, err)
	}
	hostToolsReleased := false
	defer func() {
		if !hostToolsReleased {
			if releaseErr := hostToolBinding.Release(); releaseErr != nil {
				resultErr = errors.Join(
					resultErr,
					errWindowsReleaseQualificationFixtureCleanup,
					releaseErr,
				)
			}
		}
	}()
	if err := hostToolBinding.Verify(context.Background()); err != nil {
		return nil, errors.Join(errWindowsReleaseQualificationFixture, err)
	}
	buildTimeout := request.Timeout
	if buildTimeout <= 0 {
		return nil, errWindowsReleaseQualificationFixture
	}
	if buildTimeout > 25*time.Minute {
		buildTimeout = 25 * time.Minute
	}
	buildContext, cancelBuild := context.WithTimeout(ctx, buildTimeout)
	fixture, buildErr := qualificationfixture.BuildHost(buildContext, qualificationfixture.HostBuildRequest{
		Root:          root,
		GoExecutable:  request.Application,
		GitExecutable: gitPath,
		Environment:   hostEnvironment,
	})
	cancelBuild()
	verifyHostToolsErr := hostToolBinding.Verify(context.Background())
	releaseHostToolsErr := hostToolBinding.Release()
	hostToolsReleased = true
	if releaseHostToolsErr != nil {
		return nil, errors.Join(
			errWindowsReleaseQualificationFixture,
			errWindowsReleaseQualificationFixtureCleanup,
			releaseHostToolsErr,
		)
	}
	if errors.Is(buildErr, qualificationfixture.ErrHostBuildCleanup) {
		return nil, errors.Join(
			errWindowsReleaseQualificationFixture,
			errWindowsReleaseQualificationFixtureCleanup,
			buildErr,
		)
	}
	if buildErr != nil || fixture == nil || verifyHostToolsErr != nil {
		return nil, errors.Join(
			errWindowsReleaseQualificationFixture,
			buildErr,
			verifyHostToolsErr,
		)
	}

	digest := fixture.ManifestDigest
	if fixture.Root != root || len(fixture.Files) != windowsReleaseQualificationFixtureFileCount {
		return nil, errWindowsReleaseQualificationFixture
	}
	paths := make(map[string]string, len(fixture.Files)+1)
	paths[qualificationfixture.ManifestName] = filepath.Join(root, qualificationfixture.ManifestName)
	for _, file := range fixture.Files {
		if file.RelativePath == "" || file.Path == "" {
			return nil, errWindowsReleaseQualificationFixture
		}
		paths[file.RelativePath] = file.Path
	}
	if len(paths) != len(fixture.Files)+1 {
		return nil, errWindowsReleaseQualificationFixture
	}
	fileBinding, err := newOSGateApplicationBinding(context.Background(), paths)
	if err != nil || fileBinding == nil || nilGateDependency(fileBinding) {
		return nil, errors.Join(errWindowsReleaseQualificationFixture, err)
	}
	binding := &windowsReleaseQualificationFixtureBinding{
		root:           root,
		manifestDigest: digest,
		files:          fileBinding,
		cleanup:        cleanup,
	}
	// The binding owns both the held files and staging cleanup from here.
	failed = false
	if err := binding.Verify(context.Background()); err != nil {
		releaseErr := binding.Release()
		if releaseErr != nil {
			return nil, errors.Join(
				errWindowsReleaseQualificationFixture,
				errWindowsReleaseQualificationFixtureCleanup,
				err,
				releaseErr,
			)
		}
		return nil, errors.Join(errWindowsReleaseQualificationFixture, err)
	}
	request.Env = append(
		request.Env,
		qualificationfixture.ImportRootEnv+"="+root,
		qualificationfixture.ManifestDigestEnv+"="+digest,
	)
	if !validGateProcessRequest(*request) {
		releaseErr := binding.Release()
		if releaseErr != nil {
			return nil, errors.Join(
				errWindowsReleaseQualificationFixture,
				errWindowsReleaseQualificationFixtureCleanup,
				releaseErr,
			)
		}
		return nil, errWindowsReleaseQualificationFixture
	}
	return binding, nil
}

func (binding *windowsReleaseQualificationFixtureBinding) Verify(ctx context.Context) error {
	if binding == nil || binding.released || binding.files == nil ||
		nilGateDependency(binding.files) || ctx == nil || nilGateDependency(ctx) ||
		ctx.Err() != nil {
		return errWindowsReleaseQualificationFixture
	}
	if err := binding.files.Verify(ctx); err != nil {
		return errors.Join(errWindowsReleaseQualificationFixture, err)
	}
	fixture, err := qualificationfixture.Load(binding.root, binding.manifestDigest)
	if err != nil || fixture == nil || fixture.Root != binding.root ||
		fixture.ManifestDigest != binding.manifestDigest ||
		len(fixture.Files) != windowsReleaseQualificationFixtureFileCount {
		return errors.Join(errWindowsReleaseQualificationFixture, err)
	}
	return nil
}

func (binding *windowsReleaseQualificationFixtureBinding) Release() error {
	if binding == nil || binding.released {
		return errWindowsReleaseQualificationFixture
	}
	binding.released = true
	var releaseErr error
	if binding.files == nil || nilGateDependency(binding.files) {
		releaseErr = errWindowsReleaseQualificationFixture
	} else {
		releaseErr = binding.files.Release()
	}
	binding.files = nil
	if binding.cleanup == nil {
		releaseErr = errors.Join(releaseErr, errWindowsReleaseQualificationFixture)
	} else {
		releaseErr = errors.Join(releaseErr, binding.cleanup())
	}
	binding.cleanup = nil
	binding.root = ""
	binding.manifestDigest = ""
	if releaseErr != nil {
		return errors.Join(errWindowsReleaseQualificationFixture, releaseErr)
	}
	return nil
}

func windowsReleaseQualificationHostPath(application, gitPath, systemRoot string) string {
	if !cleanAbsoluteGatePath(application) || !cleanAbsoluteGatePath(gitPath) {
		return ""
	}
	directories := []string{
		filepath.Clean(filepath.Dir(gitPath)),
		filepath.Clean(filepath.Join(systemRoot, "System32")),
	}
	seen := make(map[string]struct{}, len(directories))
	for _, path := range directories {
		if !cleanAbsoluteGatePath(path) {
			return ""
		}
		key := strings.ToLower(path)
		if _, duplicate := seen[key]; duplicate {
			return ""
		}
		seen[key] = struct{}{}
	}
	// Git must be first because go build -buildvcs=true performs its own PATH
	// lookup. PATHEXT is separately reduced to .EXE, while fixture-owned go
	// invocations use the pinned absolute Go path instead of PATH.
	return strings.Join(directories, string(os.PathListSeparator))
}

func windowsGateEnvironmentWithReplacements(
	environment []string,
	replacements map[string]string,
) ([]string, bool) {
	if len(environment) == 0 || len(replacements) == 0 {
		return nil, false
	}
	canonical := make(map[string]string, len(replacements))
	for name, value := range replacements {
		name = strings.ToUpper(name)
		if name == "" || strings.ContainsAny(name, "=\x00\r\n") ||
			strings.ContainsAny(value, "\x00\r\n") {
			return nil, false
		}
		canonical[name] = value
	}
	result := make([]string, 0, len(environment)+len(canonical))
	for _, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == "" {
			return nil, false
		}
		if _, replace := canonical[strings.ToUpper(name)]; replace {
			continue
		}
		result = append(result, entry)
	}
	names := make([]string, 0, len(canonical))
	for name := range canonical {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		result = append(result, name+"="+canonical[name])
	}
	normalized, ok := normalizeGateProcessEnvironment(result)
	return normalized, ok
}
