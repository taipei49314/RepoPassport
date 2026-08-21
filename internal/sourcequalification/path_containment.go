package sourcequalification

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/taipei49314/RepoPassport/internal/pathsecurity"
)

const maximumPackageContainmentDepth = 1024

var errPackagePathContainment = errors.New("source qualification path containment is unsafe")

// packageIdentityPathPlan binds a path to fixed-handle filesystem identities.
// ancestorIdentities starts at the target (or nearest existing directory) and
// ends at the filesystem root. missingComponents is ordered from that nearest
// existing directory toward the absent target.
type packageIdentityPathPlan struct {
	targetExists            bool
	targetDirectory         bool
	targetIdentity          packageFileIdentity
	nearestExistingIdentity packageFileIdentity
	ancestorIdentities      []packageFileIdentity
	missingComponents       []string
}

// securePackagePathContains resolves containment by filesystem identity. It
// never follows a symlink or reparse point and returns an error when either
// path, an existing ancestor, or an absence claim changes during inspection.
func securePackagePathContains(parent, child string) (bool, error) {
	if contains, handled, err := pathsecurity.QualificationPathContains(parent, child); handled {
		if err != nil {
			return false, errPackagePathContainment
		}
		return contains, nil
	}
	parentFirst, err := inspectPackageIdentityPath(parent)
	if err != nil {
		return false, errPackagePathContainment
	}
	childPlan, err := inspectPackageIdentityPath(child)
	if err != nil {
		return false, errPackagePathContainment
	}
	parentLast, err := inspectPackageIdentityPath(parent)
	if err != nil || !samePackageIdentityPathPlan(parentFirst, parentLast) {
		return false, errPackagePathContainment
	}
	return packageIdentityPlansContain(parentFirst, childPlan), nil
}

func packagePathsOverlapOrUnsafe(left, right string) bool {
	leftContains, leftErr := securePackagePathContains(left, right)
	rightContains, rightErr := securePackagePathContains(right, left)
	return leftErr != nil || rightErr != nil || leftContains || rightContains
}

func packageIdentityPlansContain(parent, child packageIdentityPathPlan) bool {
	if parent.targetExists {
		if !parent.targetDirectory {
			return child.targetExists && parent.targetIdentity == child.targetIdentity
		}
		for _, identity := range child.ancestorIdentities {
			if identity == parent.targetIdentity {
				return true
			}
		}
		return false
	}
	if child.targetExists || len(parent.missingComponents) == 0 ||
		parent.nearestExistingIdentity != child.nearestExistingIdentity ||
		len(parent.missingComponents) > len(child.missingComponents) {
		return false
	}
	for index := range parent.missingComponents {
		if !equalPackageMissingPathComponent(
			parent.missingComponents[index],
			child.missingComponents[index],
		) {
			return false
		}
	}
	return true
}

func inspectPackageIdentityPath(path string) (packageIdentityPathPlan, error) {
	canonical, err := canonicalPackageFilesystemPath(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return packageIdentityPathPlan{}, errPackagePathContainment
	}
	current := canonical
	missingReverse := make([]string, 0, 4)
	for depth := 0; depth < maximumPackageContainmentDepth; depth++ {
		_, statErr := os.Lstat(current)
		if statErr == nil {
			first, err := inspectExistingPackageIdentityPath(current)
			if err != nil {
				return packageIdentityPathPlan{}, errPackagePathContainment
			}
			second, err := inspectExistingPackageIdentityPath(current)
			if err != nil || !samePackageIdentityPathPlan(first, second) {
				return packageIdentityPathPlan{}, errPackagePathContainment
			}
			if len(missingReverse) == 0 {
				return first, nil
			}
			if !first.targetDirectory {
				return packageIdentityPathPlan{}, errPackagePathContainment
			}
			if _, err := os.Lstat(canonical); !errors.Is(err, os.ErrNotExist) {
				return packageIdentityPathPlan{}, errPackagePathContainment
			}
			missing := make([]string, len(missingReverse))
			for index := range missingReverse {
				missing[len(missingReverse)-1-index] = missingReverse[index]
			}
			return packageIdentityPathPlan{
				nearestExistingIdentity: first.targetIdentity,
				ancestorIdentities:      append([]packageFileIdentity(nil), first.ancestorIdentities...),
				missingComponents:       missing,
			}, nil
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return packageIdentityPathPlan{}, errPackagePathContainment
		}
		parent := filepath.Dir(current)
		if parent == current {
			return packageIdentityPathPlan{}, errPackagePathContainment
		}
		component := filepath.Base(current)
		if component == "" || component == "." || component == ".." {
			return packageIdentityPathPlan{}, errPackagePathContainment
		}
		missingReverse = append(missingReverse, component)
		current = parent
	}
	return packageIdentityPathPlan{}, errPackagePathContainment
}

func inspectExistingPackageIdentityPath(path string) (packageIdentityPathPlan, error) {
	identity, directory, err := openPackagePathIdentity(path)
	if err != nil {
		return packageIdentityPathPlan{}, errPackagePathContainment
	}
	result := packageIdentityPathPlan{
		targetExists:            true,
		targetDirectory:         directory,
		targetIdentity:          identity,
		nearestExistingIdentity: identity,
		ancestorIdentities:      []packageFileIdentity{identity},
	}
	current := path
	if !directory {
		current = filepath.Dir(current)
	}
	for depth := 0; depth < maximumPackageContainmentDepth; depth++ {
		if directory || depth > 0 {
			if !(directory && depth == 0) {
				ancestor, err := openPackageDirectoryIdentity(current)
				if err != nil {
					return packageIdentityPathPlan{}, errPackagePathContainment
				}
				result.ancestorIdentities = append(result.ancestorIdentities, ancestor)
			}
		} else {
			ancestor, err := openPackageDirectoryIdentity(current)
			if err != nil {
				return packageIdentityPathPlan{}, errPackagePathContainment
			}
			result.ancestorIdentities = append(result.ancestorIdentities, ancestor)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return result, nil
		}
		current = parent
	}
	return packageIdentityPathPlan{}, errPackagePathContainment
}

func openPackagePathIdentity(path string) (packageFileIdentity, bool, error) {
	directoryIdentity, directoryErr := openPackageDirectoryIdentity(path)
	if directoryErr == nil {
		return directoryIdentity, true, nil
	}
	file, err := openPackageRegularFile(path)
	if err != nil {
		return packageFileIdentity{}, false, errPackagePathContainment
	}
	info, statErr := file.Stat()
	identity, identityErr := packageFileIdentity{}, error(nil)
	if statErr == nil {
		identity, identityErr = packageContainmentFileIdentity(file, info)
	}
	closeErr := file.Close()
	if statErr != nil || identityErr != nil || closeErr != nil {
		return packageFileIdentity{}, false, errPackagePathContainment
	}
	return identity, false, nil
}

func openPackageDirectoryIdentity(path string) (packageFileIdentity, error) {
	directory, err := openPackageDirectory(path)
	if err != nil {
		return packageFileIdentity{}, errPackagePathContainment
	}
	info, statErr := directory.Stat()
	identity, identityErr := packageFileIdentity{}, error(nil)
	if statErr == nil {
		identity, identityErr = packageContainmentDirectoryIdentity(directory, info)
	}
	closeErr := directory.Close()
	if statErr != nil || identityErr != nil || closeErr != nil {
		return packageFileIdentity{}, errPackagePathContainment
	}
	return identity, nil
}

func samePackageIdentityPathPlan(left, right packageIdentityPathPlan) bool {
	if left.targetExists != right.targetExists ||
		left.targetDirectory != right.targetDirectory ||
		left.targetIdentity != right.targetIdentity ||
		left.nearestExistingIdentity != right.nearestExistingIdentity ||
		len(left.ancestorIdentities) != len(right.ancestorIdentities) ||
		len(left.missingComponents) != len(right.missingComponents) {
		return false
	}
	for index := range left.ancestorIdentities {
		if left.ancestorIdentities[index] != right.ancestorIdentities[index] {
			return false
		}
	}
	for index := range left.missingComponents {
		if left.missingComponents[index] != right.missingComponents[index] {
			return false
		}
	}
	return true
}
