//go:build windows

package windowssecurity

import (
	"strconv"
	"strings"
)

const (
	privateSystemPrincipal         = "S-1-5-18"
	privateAdministratorsPrincipal = "S-1-5-32-544"
	privateOwnerRightsPrincipal    = "S-1-3-4"
)

// PrivateDACLSDDL builds the exact protected full-access DACL used by private
// state objects. appContainer must be empty or an AppContainer package SID.
func PrivateDACLSDDL(owner, appContainer string) (string, bool) {
	if owner == "" || (appContainer != "" && !validAppContainerPackagePrincipal(appContainer)) {
		return "", false
	}
	entries := []string{"(A;;FA;;;" + owner + ")"}
	if owner != privateSystemPrincipal {
		entries = append(entries, "(A;;FA;;;SY)")
	}
	if owner != privateAdministratorsPrincipal {
		entries = append(entries, "(A;;FA;;;BA)")
	}
	if appContainer != "" && appContainer != owner &&
		appContainer != privateSystemPrincipal && appContainer != privateAdministratorsPrincipal {
		entries = append(entries, "(A;;FA;;;"+appContainer+")")
	}
	return "O:" + owner + "D:P" + strings.Join(entries, ""), true
}

// ValidPrivateDACLPrincipals accepts only the exact current principal profile.
// Legacy owner-rights descriptors remain host-only and are never accepted as
// an AppContainer profile.
func ValidPrivateDACLPrincipals(owner string, principals []string, appContainer string) bool {
	if owner == "" || len(principals) == 0 {
		return false
	}
	allowed := map[string]struct{}{
		owner:                          {},
		privateSystemPrincipal:         {},
		privateAdministratorsPrincipal: {},
		privateOwnerRightsPrincipal:    {},
	}
	if appContainer != "" {
		if !validAppContainerPackagePrincipal(appContainer) {
			return false
		}
		allowed[appContainer] = struct{}{}
	}
	actual := make(map[string]struct{}, len(principals))
	for _, principal := range principals {
		if _, permitted := allowed[principal]; !permitted {
			return false
		}
		if _, duplicate := actual[principal]; duplicate {
			return false
		}
		actual[principal] = struct{}{}
	}
	if _, legacy := actual[privateOwnerRightsPrincipal]; legacy {
		return appContainer == "" && len(actual) == 3 &&
			hasPrincipal(actual, privateOwnerRightsPrincipal) &&
			hasPrincipal(actual, privateSystemPrincipal) &&
			hasPrincipal(actual, privateAdministratorsPrincipal)
	}
	expected := map[string]struct{}{
		owner:                          {},
		privateSystemPrincipal:         {},
		privateAdministratorsPrincipal: {},
	}
	if appContainer != "" {
		expected[appContainer] = struct{}{}
	}
	if len(actual) != len(expected) {
		return false
	}
	for principal := range expected {
		if !hasPrincipal(actual, principal) {
			return false
		}
	}
	return true
}

func validAppContainerPackagePrincipal(principal string) bool {
	parts := strings.Split(principal, "-")
	if len(parts) != 11 || parts[0] != "S" || parts[1] != "1" ||
		parts[2] != "15" || parts[3] != "2" {
		return false
	}
	for _, part := range parts[3:] {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		parsed, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(parsed, 10) != part {
			return false
		}
	}
	return true
}

func hasPrincipal(principals map[string]struct{}, principal string) bool {
	_, present := principals[principal]
	return present
}
