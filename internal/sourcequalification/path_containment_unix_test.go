//go:build !windows

package sourcequalification

import "testing"

func TestPackageIdentityPlansUseDeviceInodeAncestorsNotLexicalNames(t *testing.T) {
	root := packageFileIdentity{first: 11, second: 1}
	repository := packageFileIdentity{first: 11, second: 42}
	child := packageFileIdentity{first: 11, second: 99}

	parentPlan := packageIdentityPathPlan{
		targetExists:       true,
		targetDirectory:    true,
		targetIdentity:     repository,
		ancestorIdentities: []packageFileIdentity{repository, root},
	}
	aliasChildPlan := packageIdentityPathPlan{
		targetExists:       true,
		targetDirectory:    true,
		targetIdentity:     child,
		ancestorIdentities: []packageFileIdentity{child, repository, root},
	}
	if !packageIdentityPlansContain(parentPlan, aliasChildPlan) {
		t.Fatal("device/inode-equivalent repository ancestor was not recognized")
	}

	absentAliasChild := packageIdentityPathPlan{
		nearestExistingIdentity: repository,
		ancestorIdentities:      []packageFileIdentity{repository, root},
		missingComponents:       []string{"future", "output"},
	}
	if !packageIdentityPlansContain(parentPlan, absentAliasChild) {
		t.Fatal("absent child below device/inode-equivalent repository was not recognized")
	}
}

func TestPackageIdentityPlansCompareMissingSuffixAfterSameAncestor(t *testing.T) {
	root := packageFileIdentity{first: 7, second: 1}
	parent := packageIdentityPathPlan{
		nearestExistingIdentity: root,
		ancestorIdentities:      []packageFileIdentity{root},
		missingComponents:       []string{"private", "lane"},
	}
	child := packageIdentityPathPlan{
		nearestExistingIdentity: root,
		ancestorIdentities:      []packageFileIdentity{root},
		missingComponents:       []string{"private", "lane", "output"},
	}
	sibling := packageIdentityPathPlan{
		nearestExistingIdentity: root,
		ancestorIdentities:      []packageFileIdentity{root},
		missingComponents:       []string{"private", "other"},
	}
	if !packageIdentityPlansContain(parent, child) {
		t.Fatal("missing parent suffix did not contain its planned child")
	}
	if packageIdentityPlansContain(parent, sibling) {
		t.Fatal("missing parent suffix contained a planned sibling")
	}
}
