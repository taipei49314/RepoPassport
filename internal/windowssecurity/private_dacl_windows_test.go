//go:build windows

package windowssecurity

import "testing"

func TestPrivateDACLProfilesBindExactAppContainerPrincipal(t *testing.T) {
	const (
		owner     = "S-1-5-21-100-200-300-400"
		container = "S-1-15-2-111-222-333-444-555-666-777"
	)
	want := "O:" + owner + "D:P(A;;FA;;;" + owner + ")(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + container + ")"
	got, ok := PrivateDACLSDDL(owner, container)
	if !ok || got != want {
		t.Fatalf("AppContainer private DACL = %q, want %q", got, want)
	}
	if _, ok := PrivateDACLSDDL(owner, "S-1-15-3-1"); ok {
		t.Fatal("private DACL builder accepted a capability SID")
	}
	for _, principal := range []string{
		"S-1-15-2-1",
		"S-1-15-2-111",
		"S-1-15-2-111-222-333-444-555-666-777-888",
		"S-1-15-2-not-a-number",
		"S-1-15-2-011-222-333-444-555-666-777",
		"S-1-15-2-+11-222-333-444-555-666-777",
		"S-1-15-2-4294967296-222-333-444-555-666-777",
		"S-1-5-32-544",
	} {
		if validAppContainerPackagePrincipal(principal) {
			t.Fatalf("invalid AppContainer package principal was accepted: %q", principal)
		}
		if _, ok := PrivateDACLSDDL(owner, principal); ok {
			t.Fatalf("private DACL builder accepted %q", principal)
		}
	}
	principals := []string{owner, privateSystemPrincipal, privateAdministratorsPrincipal, container}
	if !ValidPrivateDACLPrincipals(owner, principals, container) {
		t.Fatal("exact AppContainer private DACL was rejected")
	}
	for name, invalid := range map[string][]string{
		"missing package": {owner, privateSystemPrincipal, privateAdministratorsPrincipal},
		"wrong package":   {owner, privateSystemPrincipal, privateAdministratorsPrincipal, "S-1-15-2-999"},
		"world":           {owner, privateSystemPrincipal, privateAdministratorsPrincipal, container, "S-1-1-0"},
		"duplicate":       {owner, privateSystemPrincipal, privateAdministratorsPrincipal, container, container},
		"legacy":          {privateOwnerRightsPrincipal, privateSystemPrincipal, privateAdministratorsPrincipal},
	} {
		t.Run(name, func(t *testing.T) {
			if ValidPrivateDACLPrincipals(owner, invalid, container) {
				t.Fatalf("invalid AppContainer private DACL was accepted: %#v", invalid)
			}
		})
	}
}

func TestPrivateDACLProfilesPreserveHostAndLegacyContracts(t *testing.T) {
	const owner = "S-1-5-21-100-200-300-400"
	if !ValidPrivateDACLPrincipals(owner, []string{owner, privateSystemPrincipal, privateAdministratorsPrincipal}, "") {
		t.Fatal("host private DACL was rejected")
	}
	if !ValidPrivateDACLPrincipals(owner, []string{privateOwnerRightsPrincipal, privateSystemPrincipal, privateAdministratorsPrincipal}, "") {
		t.Fatal("legacy host private DACL was rejected")
	}
	if ValidPrivateDACLPrincipals(owner, []string{owner, privateSystemPrincipal, privateAdministratorsPrincipal}, "S-1-15-3-1") {
		t.Fatal("non-package capability SID was accepted as an AppContainer principal")
	}
}
