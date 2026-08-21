//go:build windows

package pathsecurity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/taipei49314/RepoPassport/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

const (
	QualificationRootsEnvironment         = "REPOPASS_WINDOWS_QUALIFICATION_ROOTS_V1"
	qualificationDescriptorVersion        = 1
	maximumQualificationRoots             = 32
	maximumQualificationDescriptor        = 16 << 10
	finalPathVolumeNameNone        uint32 = 4
)

var (
	errPathInvalid                 = errors.New("Windows path identity is invalid")
	errQualificationDescriptor     = errors.New("qualification path descriptor is invalid")
	errQualificationRootOpen       = errors.New("qualification root identity is unavailable")
	errQualificationRootAttributes = errors.New("qualification root attributes are invalid")
	errQualificationRootIdentity   = errors.New("qualification root identity changed")
	errQualificationRootFinalPath  = errors.New("qualification root final path is unavailable")

	qualificationAdapterOnce sync.Once
	qualificationAdapter     *windowsQualificationAdapter
	qualificationAdapterErr  error
)

type qualificationRootDescriptor struct {
	Path          string `json:"path"`
	Role          string `json:"role"`
	VolumeSerial  uint32 `json:"volumeSerial"`
	FileIndexHigh uint32 `json:"fileIndexHigh"`
	FileIndexLow  uint32 `json:"fileIndexLow"`
}

type qualificationRootsDescriptor struct {
	Version int                           `json:"version"`
	Roots   []qualificationRootDescriptor `json:"roots"`
}

type windowsQualificationAdapter struct {
	descriptor  string
	roots       []qualificationRootDescriptor
	rootHandles []windows.Handle
}

func Resolve(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil || !errors.Is(err, windows.ERROR_ACCESS_DENIED) || qualificationAdapter == nil {
		return resolved, err
	}
	return qualificationAdapter.resolve(path)
}

// ValidateFinalPath preserves the normal DOS-name lookup exactly. A test-only
// qualification adapter may handle only AppContainer ACCESS_DENIED failures.
func ValidateFinalPath(handle windows.Handle, expectedPath string) error {
	err := validateDOSFinalPath(handle, expectedPath)
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) || qualificationAdapter == nil {
		return errPathInvalid
	}
	return qualificationAdapter.validateFinalPath(handle, expectedPath)
}

// BuildQualificationRootsDescriptor runs on the trusted host immediately
// before AppContainer creation. It freezes the repository, common private
// environment boundary, SystemRoot, and every tool-directory identity.
func BuildQualificationRootsDescriptor(repositoryRoot string, environment []string) (string, error) {
	type qualificationPathRole struct {
		path string
		role string
	}
	paths := make([]qualificationPathRole, 0, 8)
	seen := map[string]struct{}{}
	add := func(path, role string) error {
		clean, _, ok := cleanAbsoluteDOSPath(path)
		if !ok || !validQualificationRole(role) {
			return errPathInvalid
		}
		key := strings.ToLower(clean)
		if _, exists := seen[key]; exists {
			return errPathInvalid
		}
		seen[key] = struct{}{}
		paths = append(paths, qualificationPathRole{path: clean, role: role})
		return nil
	}
	values, ok := qualificationEnvironmentValues(environment)
	if !ok || add(repositoryRoot, "repo") != nil {
		return "", errPathInvalid
	}
	privateRoot, ok := commonQualificationRoot([]string{
		values["HOME"],
		values["GOCACHE"],
		values["GOMODCACHE"],
		values["GOTMPDIR"],
	})
	if !ok || add(privateRoot, "private") != nil || add(values["SYSTEMROOT"], "system") != nil {
		return "", errPathInvalid
	}
	toolDirectories := filepath.SplitList(values["PATH"])
	if len(toolDirectories) == 0 {
		return "", errPathInvalid
	}
	for _, directory := range toolDirectories {
		if add(directory, "tool") != nil {
			return "", errPathInvalid
		}
	}

	descriptor := qualificationRootsDescriptor{
		Version: qualificationDescriptorVersion,
		Roots:   make([]qualificationRootDescriptor, 0, len(paths)),
	}
	for _, item := range paths {
		root, err := freezeHostQualificationRoot(item.path)
		if err != nil {
			return "", errPathInvalid
		}
		root.Role = item.role
		descriptor.Roots = append(descriptor.Roots, root)
	}
	sort.Slice(descriptor.Roots, func(left, right int) bool {
		return strings.ToLower(descriptor.Roots[left].Path) < strings.ToLower(descriptor.Roots[right].Path)
	})
	if !validQualificationDescriptor(descriptor) {
		return "", errPathInvalid
	}
	raw, err := json.Marshal(descriptor)
	if err != nil || len(raw) == 0 || len(raw) > maximumQualificationDescriptor {
		return "", errPathInvalid
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func qualificationEnvironmentValues(environment []string) (map[string]string, bool) {
	required := map[string]bool{
		"HOME":       true,
		"GOCACHE":    true,
		"GOMODCACHE": true,
		"GOTMPDIR":   true,
		"PATH":       true,
		"SYSTEMROOT": true,
	}
	values := make(map[string]string, len(required))
	for _, entry := range environment {
		name, value, ok := strings.Cut(entry, "=")
		name = strings.ToUpper(name)
		if !ok || !required[name] {
			continue
		}
		if value == "" || (values[name] != "" && values[name] != value) {
			return nil, false
		}
		values[name] = value
	}
	for name := range required {
		if values[name] == "" {
			return nil, false
		}
	}
	return values, true
}

func commonQualificationRoot(paths []string) (string, bool) {
	if len(paths) == 0 {
		return "", false
	}
	root, _, ok := cleanAbsoluteDOSPath(paths[0])
	if !ok {
		return "", false
	}
	for _, path := range paths[1:] {
		clean, _, cleanOK := cleanAbsoluteDOSPath(path)
		if !cleanOK || !strings.EqualFold(filepath.VolumeName(root), filepath.VolumeName(clean)) {
			return "", false
		}
		for !pathWithin(root, clean) {
			parent := filepath.Dir(root)
			if parent == root {
				return "", false
			}
			root = parent
		}
	}
	if filepath.Dir(root) == root {
		return "", false
	}
	return root, true
}

// InstallQualificationTestAdapter may be called only during test-package init.
// The sync.Once publication makes later parallel reads immutable and race-free.
func InstallQualificationTestAdapter() error {
	qualificationAdapterOnce.Do(func() {
		contained, err := windowssecurity.CurrentProcessIsAppContainer()
		if err != nil {
			qualificationAdapterErr = errQualificationDescriptor
			return
		}
		if !contained {
			return
		}
		encoded := os.Getenv(QualificationRootsEnvironment)
		if encoded == "" {
			return
		}
		descriptor, err := decodeQualificationDescriptor(encoded)
		if err != nil {
			qualificationAdapterErr = errQualificationDescriptor
			return
		}
		adapter, err := newWindowsQualificationAdapter(encoded, descriptor.Roots)
		if err != nil {
			qualificationAdapterErr = err
			return
		}
		qualificationAdapter = adapter
	})
	return qualificationAdapterErr
}

// QualificationTestDescriptor returns the immutable descriptor captured by a
// contained test binary. Production and host binaries never expose one.
func QualificationTestDescriptor() (string, bool) {
	if qualificationAdapter == nil {
		return "", false
	}
	return qualificationAdapter.descriptor, true
}

// QualificationPathBoundary returns the one host-frozen boundary with role
// that contains path. A contained test binary treats no match as invalid.
func QualificationPathBoundary(path, role string) (string, bool, error) {
	if qualificationAdapter == nil {
		return "", false, nil
	}
	clean, _, ok := cleanAbsoluteDOSPath(path)
	if !ok || (role != "repo" && role != "private" && role != "system" && role != "tool") {
		return "", true, errPathInvalid
	}
	root, ok := qualificationAdapter.uniqueRoot(clean)
	if !ok || !qualificationRootHasRole(root, role) {
		return "", true, errPathInvalid
	}
	if _, err := qualificationAdapter.validateContainmentPathForRoot(root, clean); err != nil {
		return "", true, errPathInvalid
	}
	return root.Path, true, nil
}

// QualificationPathContains provides the qualification-only replacement for
// callers whose normal Windows identity walk reaches inaccessible profile
// ancestors. Both paths remain bound to the host-frozen root identities.
func QualificationPathContains(parent, child string) (bool, bool, error) {
	if qualificationAdapter == nil {
		return false, false, nil
	}
	parentPath, _, parentOK := cleanAbsoluteDOSPath(parent)
	childPath, _, childOK := cleanAbsoluteDOSPath(child)
	if !parentOK || !childOK {
		return false, true, errPathInvalid
	}
	parentRoot, err := qualificationAdapter.validateContainmentPath(parentPath)
	if err != nil {
		return false, true, errPathInvalid
	}
	childRoot, err := qualificationAdapter.validateContainmentPath(childPath)
	if err != nil {
		return false, true, errPathInvalid
	}
	if parentRoot != childRoot || parentRoot.Role != childRoot.Role {
		return false, true, nil
	}
	return pathWithin(parentPath, childPath), true, nil
}

func freezeHostQualificationRoot(path string) (qualificationRootDescriptor, error) {
	if err := validateHostDrive(path); err != nil || validateLongPath(path) != nil ||
		validateVolumeRoot(path) != nil || validateNoReparseComponents(path, filepath.VolumeName(path)+`\`) != nil {
		return qualificationRootDescriptor{}, errPathInvalid
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !strings.EqualFold(filepath.Clean(resolved), path) {
		return qualificationRootDescriptor{}, errPathInvalid
	}
	handle, information, err := openPathIdentity(path)
	if err != nil {
		return qualificationRootDescriptor{}, errPathInvalid
	}
	defer windows.CloseHandle(handle)
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		validateDOSFinalPath(handle, path) != nil {
		return qualificationRootDescriptor{}, errPathInvalid
	}
	return qualificationRootDescriptor{
		Path:          path,
		VolumeSerial:  information.VolumeSerialNumber,
		FileIndexHigh: information.FileIndexHigh,
		FileIndexLow:  information.FileIndexLow,
	}, nil
}

func decodeQualificationDescriptor(encoded string) (qualificationRootsDescriptor, error) {
	if encoded == "" || len(encoded) > base64.RawURLEncoding.EncodedLen(maximumQualificationDescriptor) {
		return qualificationRootsDescriptor{}, errPathInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maximumQualificationDescriptor ||
		base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return qualificationRootsDescriptor{}, errPathInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var descriptor qualificationRootsDescriptor
	if err := decoder.Decode(&descriptor); err != nil {
		return qualificationRootsDescriptor{}, errPathInvalid
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || !validQualificationDescriptor(descriptor) {
		return qualificationRootsDescriptor{}, errPathInvalid
	}
	canonical, err := json.Marshal(descriptor)
	if err != nil || !bytes.Equal(canonical, raw) {
		return qualificationRootsDescriptor{}, errPathInvalid
	}
	return descriptor, nil
}

func validQualificationDescriptor(descriptor qualificationRootsDescriptor) bool {
	if descriptor.Version != qualificationDescriptorVersion || len(descriptor.Roots) == 0 ||
		len(descriptor.Roots) > maximumQualificationRoots {
		return false
	}
	roleCounts := map[string]int{}
	for index, root := range descriptor.Roots {
		clean, _, ok := cleanAbsoluteDOSPath(root.Path)
		if !ok || clean != root.Path || !validQualificationRole(root.Role) {
			return false
		}
		if index > 0 && strings.ToLower(descriptor.Roots[index-1].Path) >= strings.ToLower(root.Path) {
			return false
		}
		roleCounts[root.Role]++
	}
	if roleCounts["repo"] != 1 || roleCounts["private"] != 1 || roleCounts["system"] != 1 ||
		roleCounts["tool"] == 0 {
		return false
	}
	for left := range descriptor.Roots {
		for right := left + 1; right < len(descriptor.Roots); right++ {
			if pathWithin(descriptor.Roots[left].Path, descriptor.Roots[right].Path) ||
				pathWithin(descriptor.Roots[right].Path, descriptor.Roots[left].Path) ||
				sameQualificationRootIdentity(descriptor.Roots[left], descriptor.Roots[right]) {
				return false
			}
		}
	}
	return true
}

func validQualificationRole(role string) bool {
	return role == "repo" || role == "private" || role == "system" || role == "tool"
}

func qualificationRootHasRole(root qualificationRootDescriptor, role string) bool {
	return validQualificationRole(role) && root.Role == role
}

func newWindowsQualificationAdapter(
	descriptor string,
	roots []qualificationRootDescriptor,
) (*windowsQualificationAdapter, error) {
	if !validQualificationDescriptor(qualificationRootsDescriptor{
		Version: qualificationDescriptorVersion,
		Roots:   roots,
	}) {
		return nil, errQualificationDescriptor
	}
	adapter := &windowsQualificationAdapter{
		descriptor:  descriptor,
		roots:       append([]qualificationRootDescriptor(nil), roots...),
		rootHandles: make([]windows.Handle, len(roots)),
	}
	for index, root := range adapter.roots {
		handle, information, err := openRetainedPathIdentity(root.Path)
		if err != nil {
			adapter.closeRetainedRoots()
			return nil, errQualificationRootOpen
		}
		adapter.rootHandles[index] = handle
		if err := validateQualificationRootHandle(handle, information, root); err != nil {
			adapter.closeRetainedRoots()
			return nil, err
		}
	}
	return adapter, nil
}

func (adapter *windowsQualificationAdapter) closeRetainedRoots() {
	for index := len(adapter.rootHandles) - 1; index >= 0; index-- {
		if adapter.rootHandles[index] != 0 {
			_ = windows.CloseHandle(adapter.rootHandles[index])
			adapter.rootHandles[index] = 0
		}
	}
}

func (adapter *windowsQualificationAdapter) resolve(path string) (string, error) {
	expected, _, ok := cleanAbsoluteDOSPath(path)
	if !ok {
		return "", errPathInvalid
	}
	root, ok := adapter.uniqueRoot(expected)
	if !ok || adapter.validateCandidate(root, expected, 0) != nil {
		return "", errPathInvalid
	}
	return expected, nil
}

func (adapter *windowsQualificationAdapter) validateFinalPath(handle windows.Handle, path string) error {
	expected, _, ok := cleanAbsoluteDOSPath(path)
	if !ok {
		return errPathInvalid
	}
	root, ok := adapter.uniqueRoot(expected)
	if !ok {
		return errPathInvalid
	}
	return adapter.validateCandidate(root, expected, handle)
}

func (adapter *windowsQualificationAdapter) uniqueRoot(path string) (qualificationRootDescriptor, bool) {
	var match qualificationRootDescriptor
	matches := 0
	for _, root := range adapter.roots {
		if pathWithin(root.Path, path) {
			match = root
			matches++
		}
	}
	return match, matches == 1
}

func (adapter *windowsQualificationAdapter) validateRoot(root qualificationRootDescriptor) error {
	_, _, err := adapter.retainedRoot(root)
	return err
}

func (adapter *windowsQualificationAdapter) validateCandidate(
	root qualificationRootDescriptor,
	path string,
	expectedHandle windows.Handle,
) error {
	identity, err := adapter.openRetainedQualificationPath(root, path)
	if err != nil {
		return errPathInvalid
	}
	defer identity.close()
	if expectedHandle == 0 {
		return nil
	}
	var expectedInformation windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(expectedHandle, &expectedInformation) != nil ||
		expectedInformation.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		expectedInformation.VolumeSerialNumber != identity.information.VolumeSerialNumber ||
		expectedInformation.FileIndexHigh != identity.information.FileIndexHigh ||
		expectedInformation.FileIndexLow != identity.information.FileIndexLow ||
		validateVolumeRelativeFinalPath(expectedHandle, path) != nil {
		return errPathInvalid
	}
	return nil
}

func (adapter *windowsQualificationAdapter) validateContainmentPath(path string) (qualificationRootDescriptor, error) {
	root, ok := adapter.uniqueRoot(path)
	if !ok {
		return qualificationRootDescriptor{}, errPathInvalid
	}
	return adapter.validateContainmentPathForRoot(root, path)
}

func (adapter *windowsQualificationAdapter) validateContainmentPathForRoot(
	root qualificationRootDescriptor,
	path string,
) (qualificationRootDescriptor, error) {
	identity, missing, err := adapter.openRetainedQualificationPathPlan(root, path)
	if err != nil {
		return qualificationRootDescriptor{}, errPathInvalid
	}
	defer identity.close()
	if identity.validate(root) != nil {
		return qualificationRootDescriptor{}, errPathInvalid
	}
	if len(missing) > 0 {
		if !qualificationComponentRemainsMissing(identity.handle, identity.missingComponent) ||
			!qualificationComponentRemainsMissing(identity.handle, identity.missingComponent) ||
			identity.validate(root) != nil {
			return qualificationRootDescriptor{}, errPathInvalid
		}
	}
	return root, nil
}

type retainedQualificationPathIdentity struct {
	rootHandle       windows.Handle
	handle           windows.Handle
	information      windows.ByHandleFileInformation
	ownedHandles     []windows.Handle
	ownedPaths       []string
	ownedInformation []windows.ByHandleFileInformation
	missingComponent string
}

func (identity *retainedQualificationPathIdentity) close() {
	for index := len(identity.ownedHandles) - 1; index >= 0; index-- {
		_ = windows.CloseHandle(identity.ownedHandles[index])
	}
	identity.ownedHandles = nil
	identity.ownedPaths = nil
	identity.ownedInformation = nil
}

func (identity *retainedQualificationPathIdentity) validate(root qualificationRootDescriptor) error {
	var rootInformation windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(identity.rootHandle, &rootInformation) != nil ||
		validateQualificationRootHandle(identity.rootHandle, rootInformation, root) != nil ||
		len(identity.ownedHandles) != len(identity.ownedPaths) ||
		len(identity.ownedHandles) != len(identity.ownedInformation) {
		return errPathInvalid
	}
	for index, handle := range identity.ownedHandles {
		var information windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(handle, &information) != nil ||
			information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
			information.VolumeSerialNumber != root.VolumeSerial ||
			information.VolumeSerialNumber != identity.ownedInformation[index].VolumeSerialNumber ||
			information.FileIndexHigh != identity.ownedInformation[index].FileIndexHigh ||
			information.FileIndexLow != identity.ownedInformation[index].FileIndexLow ||
			validateVolumeRelativeFinalPath(handle, identity.ownedPaths[index]) != nil {
			return errPathInvalid
		}
	}
	return nil
}

func (adapter *windowsQualificationAdapter) openRetainedQualificationPath(
	root qualificationRootDescriptor,
	path string,
) (*retainedQualificationPathIdentity, error) {
	identity, missing, err := adapter.openRetainedQualificationPathPlan(root, path)
	if err != nil {
		return nil, err
	}
	if len(missing) != 0 {
		identity.close()
		return nil, errPathInvalid
	}
	if identity.validate(root) != nil {
		identity.close()
		return nil, errPathInvalid
	}
	return identity, nil
}

func (adapter *windowsQualificationAdapter) openRetainedQualificationPathPlan(
	root qualificationRootDescriptor,
	path string,
) (*retainedQualificationPathIdentity, []string, error) {
	components, err := qualificationRelativeComponents(root.Path, path)
	if err != nil {
		return nil, nil, errPathInvalid
	}
	rootHandle, rootInformation, err := adapter.retainedRoot(root)
	if err != nil {
		return nil, nil, errPathInvalid
	}
	identity := &retainedQualificationPathIdentity{
		rootHandle:  rootHandle,
		handle:      rootHandle,
		information: rootInformation,
	}
	current := root.Path
	for index, component := range components {
		current = filepath.Join(current, component)
		if identity.information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			identity.close()
			return nil, nil, errPathInvalid
		}
		handle, information, openErr := openRetainedRelativePathIdentity(identity.handle, component)
		if openErr != nil {
			if !qualificationPathNotFound(openErr) ||
				identity.information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
				identity.close()
				return nil, nil, errPathInvalid
			}
			missing := make([]string, 0, len(components)-index)
			missingPath := current
			missing = append(missing, missingPath)
			for _, remaining := range components[index+1:] {
				missingPath = filepath.Join(missingPath, remaining)
				missing = append(missing, missingPath)
			}
			identity.missingComponent = component
			return identity, missing, nil
		}
		identity.ownedHandles = append(identity.ownedHandles, handle)
		identity.ownedPaths = append(identity.ownedPaths, current)
		identity.ownedInformation = append(identity.ownedInformation, information)
		if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
			information.VolumeSerialNumber != root.VolumeSerial ||
			validateVolumeRelativeFinalPath(handle, current) != nil ||
			index != len(components)-1 && information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			identity.close()
			return nil, nil, errPathInvalid
		}
		identity.handle = handle
		identity.information = information
	}
	return identity, nil, nil
}

func (adapter *windowsQualificationAdapter) retainedRoot(
	root qualificationRootDescriptor,
) (windows.Handle, windows.ByHandleFileInformation, error) {
	for index, candidate := range adapter.roots {
		if candidate != root || index >= len(adapter.rootHandles) || adapter.rootHandles[index] == 0 {
			continue
		}
		handle := adapter.rootHandles[index]
		var information windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(handle, &information) != nil {
			return 0, windows.ByHandleFileInformation{}, errQualificationRootOpen
		}
		if err := validateQualificationRootHandle(handle, information, root); err != nil {
			return 0, windows.ByHandleFileInformation{}, err
		}
		return handle, information, nil
	}
	return 0, windows.ByHandleFileInformation{}, errQualificationRootOpen
}

func validateQualificationRootHandle(
	handle windows.Handle,
	information windows.ByHandleFileInformation,
	root qualificationRootDescriptor,
) error {
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errQualificationRootAttributes
	}
	if !sameIdentity(information, root) {
		return errQualificationRootIdentity
	}
	if validateVolumeRelativeFinalPath(handle, root.Path) != nil {
		return errQualificationRootFinalPath
	}
	return nil
}

func qualificationRelativeComponents(boundary, path string) ([]string, error) {
	relative, err := filepath.Rel(boundary, path)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, `..\`) {
		return nil, errPathInvalid
	}
	if relative == "." {
		return nil, nil
	}
	components := strings.Split(relative, `\`)
	if len(components) > 1024 {
		return nil, errPathInvalid
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, errPathInvalid
		}
	}
	return components, nil
}

func qualificationPathNotFound(err error) bool {
	var status windows.NTStatus
	if errors.As(err, &status) {
		err = status.Errno()
	}
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

func qualificationComponentRemainsMissing(parent windows.Handle, component string) bool {
	handle, _, err := openRetainedRelativePathIdentity(parent, component)
	if err == nil {
		_ = windows.CloseHandle(handle)
		return false
	}
	return qualificationPathNotFound(err)
}

func validateDOSFinalPath(handle windows.Handle, expectedPath string) error {
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil {
		return err
	}
	if length == 0 || length >= uint32(len(buffer)) {
		return errPathInvalid
	}
	actual := strings.TrimPrefix(windows.UTF16ToString(buffer[:length]), `\\?\`)
	expected, err := filepath.Abs(expectedPath)
	if err != nil || !strings.EqualFold(filepath.Clean(actual), filepath.Clean(expected)) {
		return errPathInvalid
	}
	return nil
}

func validateVolumeRelativeFinalPath(handle windows.Handle, expectedPath string) error {
	_, expectedTail, ok := cleanAbsoluteDOSPath(expectedPath)
	if !ok {
		return errPathInvalid
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetFinalPathNameByHandle(
		handle, &buffer[0], uint32(len(buffer)), finalPathVolumeNameNone,
	)
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		return errPathInvalid
	}
	actual := windows.UTF16ToString(buffer[:length])
	if actual == "" || !strings.HasPrefix(actual, `\`) || strings.HasPrefix(actual, `\\`) ||
		strings.Contains(actual, ":") || filepath.Clean(actual) != actual ||
		!strings.EqualFold(actual, expectedTail) {
		return errPathInvalid
	}
	return nil
}

func validateLongPath(path string) error {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errPathInvalid
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetLongPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || length == 0 || length >= uint32(len(buffer)) ||
		!strings.EqualFold(windows.UTF16ToString(buffer[:length]), path) {
		return errPathInvalid
	}
	return nil
}

func validateVolumeRoot(path string) error {
	volume := filepath.VolumeName(path)
	root := volume + `\`
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errPathInvalid
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	if err := windows.GetVolumePathName(pointer, &buffer[0], uint32(len(buffer))); err != nil ||
		!strings.EqualFold(windows.UTF16ToString(buffer), root) {
		return errPathInvalid
	}
	rootPointer, err := windows.UTF16PtrFromString(root)
	if err != nil || windows.GetDriveType(rootPointer) != windows.DRIVE_FIXED {
		return errPathInvalid
	}
	return nil
}

func validateHostDrive(path string) error {
	volume := filepath.VolumeName(path)
	pointer, err := windows.UTF16PtrFromString(volume)
	if err != nil {
		return errPathInvalid
	}
	buffer := make([]uint16, 4096)
	length, err := windows.QueryDosDevice(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || length == 0 || int(length) > len(buffer) {
		return errPathInvalid
	}
	targets := multiString(buffer[:length])
	if len(targets) != 1 || !realWindowsVolumeTarget(targets[0]) {
		return errPathInvalid
	}
	return nil
}

func realWindowsVolumeTarget(target string) bool {
	const prefix = `\Device\HarddiskVolume`
	if !strings.HasPrefix(target, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(target, prefix)
	if suffix == "" {
		return false
	}
	_, err := strconv.ParseUint(suffix, 10, 32)
	return err == nil
}

func validateNoReparseComponents(path, boundary string) error {
	handle, _, err := validateNoReparseComponentsAndOpen(path, boundary)
	if handle != 0 {
		_ = windows.CloseHandle(handle)
	}
	return err
}

func validateNoReparseComponentsAndOpen(path, boundary string) (windows.Handle, windows.ByHandleFileInformation, error) {
	relative, err := filepath.Rel(boundary, path)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, `..\`) {
		return 0, windows.ByHandleFileInformation{}, errPathInvalid
	}
	components := []string{}
	if relative != "." {
		components = strings.Split(relative, `\`)
	}
	current := boundary
	var final windows.Handle
	var information windows.ByHandleFileInformation
	for index := 0; index <= len(components); index++ {
		if index > 0 {
			current = filepath.Join(current, components[index-1])
		}
		handle, currentInformation, openErr := openPathIdentity(current)
		if openErr != nil || currentInformation.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			if handle != 0 {
				_ = windows.CloseHandle(handle)
			}
			return 0, windows.ByHandleFileInformation{}, errPathInvalid
		}
		if index != len(components) {
			_ = windows.CloseHandle(handle)
			continue
		}
		final, information = handle, currentInformation
	}
	return final, information, nil
}

func openPathIdentity(path string) (windows.Handle, windows.ByHandleFileInformation, error) {
	return openPathIdentityWithShare(
		path,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
	)
}

func openRetainedPathIdentity(path string) (windows.Handle, windows.ByHandleFileInformation, error) {
	return openPathIdentityWithShare(path, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
}

func openRetainedRelativePathIdentity(
	parent windows.Handle,
	component string,
) (windows.Handle, windows.ByHandleFileInformation, error) {
	if component == "" || component == "." || component == ".." ||
		strings.ContainsAny(component, `\/:`) || strings.IndexByte(component, 0) >= 0 {
		return 0, windows.ByHandleFileInformation{}, errPathInvalid
	}
	name, err := windows.NewNTUnicodeString(component)
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, errPathInvalid
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    name,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.FILE_READ_ATTRIBUTES,
		&attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT,
		0,
		0,
	)
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, windows.ByHandleFileInformation{}, err
	}
	return handle, information, nil
}

func openPathIdentityWithShare(
	path string,
	shareMode uint32,
) (windows.Handle, windows.ByHandleFileInformation, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, errPathInvalid
	}
	handle, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES,
		shareMode,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, windows.ByHandleFileInformation{}, err
	}
	return handle, information, nil
}

func sameIdentity(information windows.ByHandleFileInformation, root qualificationRootDescriptor) bool {
	return information.VolumeSerialNumber == root.VolumeSerial &&
		information.FileIndexHigh == root.FileIndexHigh &&
		information.FileIndexLow == root.FileIndexLow
}

func sameQualificationRootIdentity(left, right qualificationRootDescriptor) bool {
	return left.VolumeSerial == right.VolumeSerial &&
		left.FileIndexHigh == right.FileIndexHigh &&
		left.FileIndexLow == right.FileIndexLow
}

func cleanAbsoluteDOSPath(path string) (string, string, bool) {
	if path == "" || strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", "", false
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' ||
		!((volume[0] >= 'A' && volume[0] <= 'Z') || (volume[0] >= 'a' && volume[0] <= 'z')) {
		return "", "", false
	}
	tail := strings.TrimPrefix(path, volume)
	if !strings.HasPrefix(tail, `\`) || strings.HasPrefix(tail, `\\`) ||
		strings.Contains(tail, ":") || filepath.Clean(tail) != tail {
		return "", "", false
	}
	return path, tail, true
}

func pathWithin(parent, candidate string) bool {
	relative, err := filepath.Rel(parent, candidate)
	return err == nil && !filepath.IsAbs(relative) &&
		(relative == "." || relative != ".." && !strings.HasPrefix(relative, `..\`))
}

func multiString(buffer []uint16) []string {
	var result []string
	start := 0
	for index, value := range buffer {
		if value != 0 {
			continue
		}
		if index == start {
			break
		}
		result = append(result, windows.UTF16ToString(buffer[start:index]))
		start = index + 1
	}
	return result
}
