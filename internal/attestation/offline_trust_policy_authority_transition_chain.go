package attestation

import (
	"bytes"
	"encoding/base64"
	"errors"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
	"github.com/taipei49314/RepoPassport/schemas"
)

const (
	OfflineTrustPolicyAuthorityTransitionChainPurpose  = "offline-trust-policy-authority-rotation-chain"
	OfflineTrustPolicyAuthorityTransitionChainMinHops  = 2
	OfflineTrustPolicyAuthorityTransitionChainMaxHops  = 8
	MaxOfflineTrustPolicyAuthorityTransitionChainBytes = 256 << 10

	offlineTrustPolicyAuthorityTransitionChainDigestTag = "repopass.offline-trust-policy-authority-transition-chain.v1\x00"
)

var ErrOfflineTrustPolicyAuthorityTransitionChainInvalid = errors.New("offline trust policy authority transition chain is invalid")

// ReadTrustPolicyAuthorityTransitionChain reads only a bounded, stable,
// unlinked regular file. Canonical transport shape and ordered authentication
// are checked later against the explicit root and terminal key.
func ReadTrustPolicyAuthorityTransitionChain(path string) ([]byte, error) {
	if !safeNativePath(path) {
		return nil, untrustedError("The offline trust-policy authority transition chain path is unsupported.")
	}
	raw, err := readStableRegularFile(path, MaxOfflineTrustPolicyAuthorityTransitionChainBytes)
	if err != nil || len(raw) == 0 {
		return nil, untrustedError("The offline trust-policy authority transition chain must be a bounded stable regular file that does not resolve through a link or reparse point.")
	}
	return raw, nil
}

// OfflineTrustPolicyAuthorityTransitionChain is an unsigned canonical
// transport. Embedded keys acquire trust only through ordered verification of
// every signed offline trust-policy authority transition from an explicit
// caller-supplied root.
type OfflineTrustPolicyAuthorityTransitionChain struct {
	SchemaVersion     string                                          `json:"schemaVersion"`
	Purpose           string                                          `json:"purpose"`
	PolicyPayloadType string                                          `json:"policyPayloadType"`
	Hops              []OfflineTrustPolicyAuthorityTransitionChainHop `json:"hops"`
}

type OfflineTrustPolicyAuthorityTransitionChainHop struct {
	TransitionEnvelope string `json:"transitionEnvelope"`
	NextAuthoritySPKI  string `json:"nextAuthoritySpkiPem"`
}

// VerifiedOfflineTrustPolicyAuthorityTransitionChain exposes only facts
// authenticated after the complete bounded chain and terminal constraints
// pass.
type VerifiedOfflineTrustPolicyAuthorityTransitionChain struct {
	rootAuthorityKeyID     string
	terminalAuthorityKeyID string
	terminalGeneration     uint64
	hopCount               uint64
	digest                 string
	authorityKeyIDs        []string
}

func (v *VerifiedOfflineTrustPolicyAuthorityTransitionChain) RootAuthorityKeyID() string {
	if v == nil {
		return ""
	}
	return v.rootAuthorityKeyID
}

func (v *VerifiedOfflineTrustPolicyAuthorityTransitionChain) TerminalAuthorityKeyID() string {
	if v == nil {
		return ""
	}
	return v.terminalAuthorityKeyID
}

func (v *VerifiedOfflineTrustPolicyAuthorityTransitionChain) TerminalGeneration() uint64 {
	if v == nil {
		return 0
	}
	return v.terminalGeneration
}

func (v *VerifiedOfflineTrustPolicyAuthorityTransitionChain) HopCount() uint64 {
	if v == nil {
		return 0
	}
	return v.hopCount
}

func (v *VerifiedOfflineTrustPolicyAuthorityTransitionChain) Digest() string {
	if v == nil {
		return ""
	}
	return v.digest
}

// AuthorityKeyIDs returns the authenticated authority IDs in root-through-
// terminal order. The returned slice never aliases verifier-owned state.
func (v *VerifiedOfflineTrustPolicyAuthorityTransitionChain) AuthorityKeyIDs() []string {
	if v == nil {
		return nil
	}
	return append([]string(nil), v.authorityKeyIDs...)
}

// BuildOfflineTrustPolicyAuthorityTransitionChain authenticates every
// authoring input before returning the canonical unsigned transport.
func BuildOfflineTrustPolicyAuthorityTransitionChain(hopEnvelopes, hopNextAuthoritySPKIs [][]byte, explicitRootSPKI []byte) ([]byte, error) {
	if len(hopEnvelopes) < OfflineTrustPolicyAuthorityTransitionChainMinHops ||
		len(hopEnvelopes) > OfflineTrustPolicyAuthorityTransitionChainMaxHops ||
		len(hopEnvelopes) != len(hopNextAuthoritySPKIs) {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
	}

	hops := make([]OfflineTrustPolicyAuthorityTransitionChainHop, len(hopEnvelopes))
	for i := range hopEnvelopes {
		if len(hopEnvelopes[i]) == 0 || len(hopEnvelopes[i]) > MaxOfflineTrustPolicyAuthorityTransitionEnvelopeBytes ||
			len(hopNextAuthoritySPKIs[i]) == 0 || len(hopNextAuthoritySPKIs[i]) > MaxPublicKeyBytes {
			return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
		}
		hops[i] = OfflineTrustPolicyAuthorityTransitionChainHop{
			TransitionEnvelope: base64.StdEncoding.EncodeToString(hopEnvelopes[i]),
			NextAuthoritySPKI:  base64.StdEncoding.EncodeToString(hopNextAuthoritySPKIs[i]),
		}
	}

	raw, err := canonicaljson.Marshal(OfflineTrustPolicyAuthorityTransitionChain{
		SchemaVersion:     "1",
		Purpose:           OfflineTrustPolicyAuthorityTransitionChainPurpose,
		PolicyPayloadType: SignedOfflineTrustPolicyPayloadType,
		Hops:              hops,
	})
	if err != nil || len(raw) > MaxOfflineTrustPolicyAuthorityTransitionChainBytes {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
	}
	if _, err := VerifyOfflineTrustPolicyAuthorityTransitionChain(
		raw,
		explicitRootSPKI,
		hopNextAuthoritySPKIs[len(hopNextAuthoritySPKIs)-1],
		1,
	); err != nil {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
	}
	return raw, nil
}

// VerifyOfflineTrustPolicyAuthorityTransitionChain validates the complete
// canonical chain from the explicit root. No embedded key is trusted until
// the preceding authenticated transition names that exact canonical SPKI.
func VerifyOfflineTrustPolicyAuthorityTransitionChain(raw, explicitRootSPKI, explicitTerminalSPKI []byte, minimumGeneration uint64) (*VerifiedOfflineTrustPolicyAuthorityTransitionChain, error) {
	if minimumGeneration == 0 || minimumGeneration > MaxTrustPolicyGeneration ||
		len(raw) == 0 || len(raw) > MaxOfflineTrustPolicyAuthorityTransitionChainBytes ||
		bytes.Contains(raw, []byte{'\r'}) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) ||
		schemas.ValidateOfflineTrustPolicyAuthorityTransitionChainV1JSON(raw) != nil {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
	}

	var chain OfflineTrustPolicyAuthorityTransitionChain
	if err := decodeCanonicalJSON(raw, MaxOfflineTrustPolicyAuthorityTransitionChainBytes, &chain); err != nil ||
		validateOfflineTrustPolicyAuthorityTransitionChain(chain) != nil {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
	}

	_, rootDER, err := parsePublicKey(explicitRootSPKI)
	if err != nil {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
	}
	_, terminalDER, err := parsePublicKey(explicitTerminalSPKI)
	if err != nil {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
	}
	rootID, terminalID := digestBytes(rootDER), digestBytes(terminalDER)
	if rootID == terminalID {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
	}

	seen := map[string]struct{}{rootID: {}}
	authorityKeyIDs := make([]string, 1, len(chain.Hops)+1)
	authorityKeyIDs[0] = rootID
	currentSPKI := explicitRootSPKI
	previousGeneration := uint64(0)
	for i := range chain.Hops {
		envelopeRaw, ok := decodeOfflineTrustPolicyAuthorityTransitionChainBase64(
			chain.Hops[i].TransitionEnvelope,
			MaxOfflineTrustPolicyAuthorityTransitionEnvelopeBytes,
		)
		if !ok {
			return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
		}
		nextSPKI, ok := decodeOfflineTrustPolicyAuthorityTransitionChainBase64(
			chain.Hops[i].NextAuthoritySPKI,
			MaxPublicKeyBytes,
		)
		if !ok {
			return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
		}
		_, nextDER, err := parsePublicKey(nextSPKI)
		if err != nil {
			return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
		}
		nextID := digestBytes(nextDER)
		if _, exists := seen[nextID]; exists {
			return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
		}

		verified, err := VerifyOfflineTrustPolicyAuthorityTransition(envelopeRaw, currentSPKI, nextSPKI, 1)
		if err != nil || verified.Generation() <= previousGeneration {
			return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
		}
		seen[nextID] = struct{}{}
		authorityKeyIDs = append(authorityKeyIDs, nextID)
		currentSPKI = nextSPKI
		previousGeneration = verified.Generation()
	}

	if previousGeneration < minimumGeneration || !bytes.Equal(currentSPKI, explicitTerminalSPKI) {
		return nil, ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
	}
	digestInput := make([]byte, 0, len(offlineTrustPolicyAuthorityTransitionChainDigestTag)+len(raw))
	digestInput = append(digestInput, offlineTrustPolicyAuthorityTransitionChainDigestTag...)
	digestInput = append(digestInput, raw...)
	return &VerifiedOfflineTrustPolicyAuthorityTransitionChain{
		rootAuthorityKeyID:     rootID,
		terminalAuthorityKeyID: terminalID,
		terminalGeneration:     previousGeneration,
		hopCount:               uint64(len(chain.Hops)),
		digest:                 digestBytes(digestInput),
		authorityKeyIDs:        authorityKeyIDs,
	}, nil
}

func validateOfflineTrustPolicyAuthorityTransitionChain(chain OfflineTrustPolicyAuthorityTransitionChain) error {
	if chain.SchemaVersion != "1" || chain.Purpose != OfflineTrustPolicyAuthorityTransitionChainPurpose ||
		chain.PolicyPayloadType != SignedOfflineTrustPolicyPayloadType ||
		len(chain.Hops) < OfflineTrustPolicyAuthorityTransitionChainMinHops ||
		len(chain.Hops) > OfflineTrustPolicyAuthorityTransitionChainMaxHops {
		return ErrOfflineTrustPolicyAuthorityTransitionChainInvalid
	}
	return nil
}

func decodeOfflineTrustPolicyAuthorityTransitionChainBase64(encoded string, maximum int) ([]byte, bool) {
	if encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maximum || base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, false
	}
	return raw, true
}
