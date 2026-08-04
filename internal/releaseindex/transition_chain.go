package releaseindex

import (
	"bytes"
	"encoding/base64"
	"errors"

	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/schemas"
)

const (
	AuthorityTransitionChainPurpose   = "release-policy-authority-rotation-chain"
	AuthorityTransitionChainMinHops   = 2
	AuthorityTransitionChainMaxHops   = 8
	MaxAuthorityTransitionChainBytes  = 256 << 10
	authorityTransitionChainDigestTag = "repopass.release-authority-transition-chain.v1\x00"
)

var ErrAuthorityTransitionChainInvalid = errors.New("release authority transition chain is invalid")

// AuthorityTransitionChain is an unsigned canonical transport. Its embedded
// keys acquire trust only by successful ordered verification of every signed
// v1 transition from an explicit caller-supplied root.
type AuthorityTransitionChain struct {
	SchemaVersion string                        `json:"schemaVersion"`
	Product       string                        `json:"product"`
	Channel       string                        `json:"channel"`
	Purpose       string                        `json:"purpose"`
	Hops          []AuthorityTransitionChainHop `json:"hops"`
}

type AuthorityTransitionChainHop struct {
	TransitionEnvelope string `json:"transitionEnvelope"`
	NextAuthoritySPKI  string `json:"nextAuthoritySpkiPem"`
}

// VerifiedAuthorityTransitionChain contains only facts authenticated from the
// explicit root after the complete bounded chain and terminal constraints pass.
type VerifiedAuthorityTransitionChain struct {
	rootAuthorityKeyID     string
	terminalAuthorityKeyID string
	terminalGeneration     uint64
	hopCount               uint64
	digest                 string
}

func DefaultAuthorityTransitionChainScope() Scope {
	return Scope{Product: Product, Channel: Channel, Purpose: AuthorityTransitionChainPurpose}
}

func (v *VerifiedAuthorityTransitionChain) RootAuthorityKeyID() string {
	if v == nil {
		return ""
	}
	return v.rootAuthorityKeyID
}

func (v *VerifiedAuthorityTransitionChain) TerminalAuthorityKeyID() string {
	if v == nil {
		return ""
	}
	return v.terminalAuthorityKeyID
}

func (v *VerifiedAuthorityTransitionChain) TerminalGeneration() uint64 {
	if v == nil {
		return 0
	}
	return v.terminalGeneration
}

func (v *VerifiedAuthorityTransitionChain) HopCount() uint64 {
	if v == nil {
		return 0
	}
	return v.hopCount
}

func (v *VerifiedAuthorityTransitionChain) Digest() string {
	if v == nil {
		return ""
	}
	return v.digest
}

// BuildAuthorityTransitionChain authenticates all authoring inputs before it
// returns their canonical unsigned transport.
func BuildAuthorityTransitionChain(hopEnvelopes, hopNextAuthoritySPKIs [][]byte, explicitRootSPKI []byte, scope Scope) ([]byte, error) {
	if len(hopEnvelopes) < AuthorityTransitionChainMinHops || len(hopEnvelopes) > AuthorityTransitionChainMaxHops ||
		len(hopEnvelopes) != len(hopNextAuthoritySPKIs) || scope != DefaultAuthorityTransitionChainScope() {
		return nil, ErrAuthorityTransitionChainInvalid
	}
	hops := make([]AuthorityTransitionChainHop, len(hopEnvelopes))
	for i := range hopEnvelopes {
		if len(hopEnvelopes[i]) == 0 || len(hopEnvelopes[i]) > MaxAuthorityTransitionEnvelopeBytes ||
			len(hopNextAuthoritySPKIs[i]) == 0 || len(hopNextAuthoritySPKIs[i]) > MaxPublicKeyBytes {
			return nil, ErrAuthorityTransitionChainInvalid
		}
		hops[i] = AuthorityTransitionChainHop{
			TransitionEnvelope: base64.StdEncoding.EncodeToString(hopEnvelopes[i]),
			NextAuthoritySPKI:  base64.StdEncoding.EncodeToString(hopNextAuthoritySPKIs[i]),
		}
	}
	chain := AuthorityTransitionChain{
		SchemaVersion: SchemaVersion,
		Product:       Product,
		Channel:       Channel,
		Purpose:       AuthorityTransitionChainPurpose,
		Hops:          hops,
	}
	raw, err := canonicaljson.Marshal(chain)
	if err != nil || len(raw) > MaxAuthorityTransitionChainBytes {
		return nil, ErrAuthorityTransitionChainInvalid
	}
	if _, err := VerifyAuthorityTransitionChain(raw, explicitRootSPKI, hopNextAuthoritySPKIs[len(hopNextAuthoritySPKIs)-1], scope, 1); err != nil {
		return nil, ErrAuthorityTransitionChainInvalid
	}
	return raw, nil
}

// VerifyAuthorityTransitionChain validates the complete canonical chain from
// the explicit root. No embedded key is used until the preceding authenticated
// transition names its exact canonical SPKI key ID.
func VerifyAuthorityTransitionChain(raw, explicitRootSPKI, explicitTerminalSPKI []byte, scope Scope, minimumGeneration uint64) (*VerifiedAuthorityTransitionChain, error) {
	if scope != DefaultAuthorityTransitionChainScope() || !validGeneration(minimumGeneration) ||
		len(raw) == 0 || len(raw) > MaxAuthorityTransitionChainBytes ||
		schemas.ValidateReleaseAuthorityTransitionChainV1JSON(raw) != nil {
		return nil, ErrAuthorityTransitionChainInvalid
	}
	var chain AuthorityTransitionChain
	if err := decodeExact(raw, &chain); err != nil || validateAuthorityTransitionChainShape(chain) != nil {
		return nil, ErrAuthorityTransitionChainInvalid
	}
	canonical, err := canonicaljson.Marshal(chain)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrAuthorityTransitionChainInvalid
	}
	_, rootDER, err := parseCanonicalSPKI(explicitRootSPKI)
	if err != nil {
		return nil, ErrAuthorityTransitionChainInvalid
	}
	_, terminalDER, err := parseCanonicalSPKI(explicitTerminalSPKI)
	if err != nil {
		return nil, ErrAuthorityTransitionChainInvalid
	}
	rootID, terminalID := digest(rootDER), digest(terminalDER)
	seen := map[string]struct{}{rootID: {}}
	currentSPKI := explicitRootSPKI
	previousGeneration := uint64(0)
	for i := range chain.Hops {
		envelopeRaw, ok := decodeCanonicalBase64(chain.Hops[i].TransitionEnvelope, MaxAuthorityTransitionEnvelopeBytes)
		if !ok {
			return nil, ErrAuthorityTransitionChainInvalid
		}
		nextSPKI, ok := decodeCanonicalBase64(chain.Hops[i].NextAuthoritySPKI, MaxPublicKeyBytes)
		if !ok {
			return nil, ErrAuthorityTransitionChainInvalid
		}
		_, nextDER, err := parseCanonicalSPKI(nextSPKI)
		if err != nil {
			return nil, ErrAuthorityTransitionChainInvalid
		}
		nextID := digest(nextDER)
		if _, exists := seen[nextID]; exists {
			return nil, ErrAuthorityTransitionChainInvalid
		}
		verified, err := VerifyAuthorityTransition(
			envelopeRaw, currentSPKI, nextSPKI,
			DefaultAuthorityTransitionScope(), 1,
		)
		if err != nil || verified.Generation() <= previousGeneration {
			return nil, ErrAuthorityTransitionChainInvalid
		}
		seen[nextID] = struct{}{}
		currentSPKI = nextSPKI
		previousGeneration = verified.Generation()
	}
	if previousGeneration < minimumGeneration || terminalID == rootID ||
		!bytes.Equal(currentSPKI, explicitTerminalSPKI) {
		return nil, ErrAuthorityTransitionChainInvalid
	}
	return &VerifiedAuthorityTransitionChain{
		rootAuthorityKeyID:     rootID,
		terminalAuthorityKeyID: terminalID,
		terminalGeneration:     previousGeneration,
		hopCount:               uint64(len(chain.Hops)),
		digest:                 digest(append([]byte(authorityTransitionChainDigestTag), raw...)),
	}, nil
}

func validateAuthorityTransitionChainShape(chain AuthorityTransitionChain) error {
	if chain.SchemaVersion != SchemaVersion || chain.Product != Product || chain.Channel != Channel ||
		chain.Purpose != AuthorityTransitionChainPurpose || len(chain.Hops) < AuthorityTransitionChainMinHops ||
		len(chain.Hops) > AuthorityTransitionChainMaxHops {
		return ErrAuthorityTransitionChainInvalid
	}
	return nil
}

func decodeCanonicalBase64(encoded string, maximum int) ([]byte, bool) {
	if encoded == "" {
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maximum || base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, false
	}
	return raw, true
}
