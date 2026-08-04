// Package releaseindex implements the purpose-separated Alpha.33 external
// release index. Trust is always rooted in an authority SPKI supplied by the
// caller; a release signer SPKI is never an authority by itself.
package releaseindex

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/repopass/repopass/internal/canonicaljson"
	"github.com/repopass/repopass/schemas"
)

const (
	SchemaVersion                 = "1"
	Product                       = "repopass"
	Channel                       = "alpha"
	Purpose                       = "release-index-signing"
	ProductVersion                = "0.1.0-alpha.33"
	IndexArtifactType             = "repopass.external-release-index"
	IndexPayloadType              = "application/vnd.repopass.release-index.v1+json"
	PolicyPayloadType             = "application/vnd.repopass.release-key-policy.v1+json"
	MaxIndexBytes                 = 1 << 20
	MaxEnvelopeBytes              = 1400 << 10
	MaxPolicyBytes                = 64 << 10
	MaxPolicyEnvelopeBytes        = 96 << 10
	MaxGeneration          uint64 = 9007199254740991
	MaxFiles                      = 128
	MaxPolicyKeys                 = 32
)

var (
	ErrIndexInvalid     = errors.New("release index is invalid")
	ErrPolicyInvalid    = errors.New("release key policy is invalid")
	ErrSignatureInvalid = errors.New("release signature is invalid")
	ErrReleaseUntrusted = errors.New("release signer is not authorized")
	ErrArtifactsInvalid = errors.New("release artifacts are invalid")
	ErrReadFailed       = errors.New("release input cannot be read safely")
	ErrPublishFailed    = errors.New("signed release sidecars cannot be published safely")
	ErrSigningFailed    = errors.New("release signing failed")
)

type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
}

type TrustBoundary struct {
	Capability          string `json:"capability"`
	FormalClaim         bool   `json:"formalClaim"`
	IdentityAttestation string `json:"identityAttestation"`
	Overall             string `json:"overall"`
	TimeAttestation     string `json:"timeAttestation"`
}

type Index struct {
	ArtifactType      string        `json:"artifactType"`
	Channel           string        `json:"channel"`
	Files             []FileEntry   `json:"files"`
	Product           string        `json:"product"`
	ProductVersion    string        `json:"productVersion"`
	ReleaseGeneration uint64        `json:"releaseGeneration"`
	SchemaVersion     string        `json:"schemaVersion"`
	TrustBoundary     TrustBoundary `json:"trustBoundary"`
}

type PolicyKey struct {
	KeyID  string `json:"keyId"`
	Status string `json:"status"`
}

type Policy struct {
	SchemaVersion  string      `json:"schemaVersion"`
	Product        string      `json:"product"`
	Channel        string      `json:"channel"`
	Purpose        string      `json:"purpose"`
	Generation     uint64      `json:"generation"`
	KeyAlgorithm   string      `json:"keyAlgorithm"`
	KeyIDAlgorithm string      `json:"keyIdAlgorithm"`
	Keys           []PolicyKey `json:"keys"`
}

type Scope struct {
	Product string
	Channel string
	Purpose string
}

func DefaultScope() Scope { return Scope{Product: Product, Channel: Channel, Purpose: Purpose} }

type envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []signature `json:"signatures"`
}

type signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type VerifiedPolicy struct {
	policy         Policy
	statuses       map[string]string
	authorityKeyID string
	payloadDigest  string
	envelopeDigest string
}

func (p *VerifiedPolicy) AuthorityKeyID() string {
	if p == nil {
		return ""
	}
	return p.authorityKeyID
}
func (p *VerifiedPolicy) Generation() uint64 {
	if p == nil {
		return 0
	}
	return p.policy.Generation
}
func (p *VerifiedPolicy) PayloadDigest() string {
	if p == nil {
		return ""
	}
	return p.payloadDigest
}
func (p *VerifiedPolicy) EnvelopeDigest() string {
	if p == nil {
		return ""
	}
	return p.envelopeDigest
}
func (p *VerifiedPolicy) Scope() Scope {
	if p == nil {
		return Scope{}
	}
	return Scope{Product: p.policy.Product, Channel: p.policy.Channel, Purpose: p.policy.Purpose}
}

type TrustDecision string

const (
	TrustDecisionTrusted   TrustDecision = "trusted"
	TrustDecisionRevoked   TrustDecision = "revoked"
	TrustDecisionNotListed TrustDecision = "not-listed"
)

func (p *VerifiedPolicy) EvaluateSignerKeyID(keyID string) (TrustDecision, error) {
	if p == nil || !validDigest(keyID) {
		return TrustDecisionNotListed, ErrPolicyInvalid
	}
	switch p.statuses[keyID] {
	case "trusted":
		return TrustDecisionTrusted, nil
	case "revoked":
		return TrustDecisionRevoked, nil
	default:
		return TrustDecisionNotListed, nil
	}
}

type VerifiedIndex struct {
	index          Index
	indexRaw       []byte
	indexDigest    string
	envelopeDigest string
	signerKeyID    string
}

// AuthenticatedIndex contains only index and release-signer facts established
// by canonical parsing and DSSE authentication. It deliberately carries no
// policy authorization decision, so callers can authenticate before policy
// I/O and durable policy-state observation.
type AuthenticatedIndex struct {
	index                    Index
	indexRaw                 []byte
	indexDigest              string
	envelopeDigest           string
	signerKeyID              string
	minimumReleaseGeneration uint64
}

func (a *AuthenticatedIndex) ReleaseGeneration() uint64 {
	if a == nil {
		return 0
	}
	return a.index.ReleaseGeneration
}
func (a *AuthenticatedIndex) IndexDigest() string {
	if a == nil {
		return ""
	}
	return a.indexDigest
}
func (a *AuthenticatedIndex) EnvelopeDigest() string {
	if a == nil {
		return ""
	}
	return a.envelopeDigest
}
func (a *AuthenticatedIndex) SignerKeyID() string {
	if a == nil {
		return ""
	}
	return a.signerKeyID
}
func (a *AuthenticatedIndex) Scope() Scope {
	if a == nil {
		return Scope{}
	}
	return Scope{Product: a.index.Product, Channel: a.index.Channel, Purpose: Purpose}
}
func (a *AuthenticatedIndex) Index() Index {
	if a == nil {
		return Index{}
	}
	return cloneIndex(a.index)
}

func (v *VerifiedIndex) ReleaseGeneration() uint64 {
	if v == nil {
		return 0
	}
	return v.index.ReleaseGeneration
}
func (v *VerifiedIndex) IndexDigest() string {
	if v == nil {
		return ""
	}
	return v.indexDigest
}
func (v *VerifiedIndex) EnvelopeDigest() string {
	if v == nil {
		return ""
	}
	return v.envelopeDigest
}
func (v *VerifiedIndex) SignerKeyID() string {
	if v == nil {
		return ""
	}
	return v.signerKeyID
}
func (v *VerifiedIndex) Scope() Scope {
	if v == nil {
		return Scope{}
	}
	return Scope{Product: v.index.Product, Channel: v.index.Channel, Purpose: Purpose}
}
func (v *VerifiedIndex) Index() Index {
	if v == nil {
		return Index{}
	}
	return cloneIndex(v.index)
}

func BuildIndex(root, productVersion string, releaseGeneration uint64) ([]byte, error) {
	if productVersion != ProductVersion || !validGeneration(releaseGeneration) {
		return nil, ErrIndexInvalid
	}
	entries, err := inspectArtifactRoot(root, nil)
	if err != nil {
		return nil, ErrArtifactsInvalid
	}
	index := Index{
		ArtifactType: IndexArtifactType, Channel: Channel, Files: entries,
		Product: Product, ProductVersion: productVersion,
		ReleaseGeneration: releaseGeneration, SchemaVersion: SchemaVersion,
		TrustBoundary: requiredTrustBoundary(),
	}
	if err := validateIndex(index); err != nil {
		return nil, ErrIndexInvalid
	}
	raw, err := canonicaljson.Marshal(index)
	if err != nil || len(raw) > MaxIndexBytes {
		return nil, ErrIndexInvalid
	}
	return raw, nil
}

func ParseIndex(raw []byte) (*Index, error) {
	if !validRawJSON(raw, MaxIndexBytes) || schemas.ValidateReleaseIndexV1JSON(raw) != nil {
		return nil, ErrIndexInvalid
	}
	var index Index
	if err := decodeExact(raw, &index); err != nil || validateIndex(index) != nil {
		return nil, ErrIndexInvalid
	}
	canonical, err := canonicaljson.Marshal(index)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrIndexInvalid
	}
	return &index, nil
}

// ParsePolicyPayload is an authoring helper. Verification callers must use
// VerifyPolicy, which authenticates the opaque DSSE payload before calling the
// same strict parser internally.
func ParsePolicyPayload(raw []byte) (*Policy, error) {
	if !validRawJSON(raw, MaxPolicyBytes) || schemas.ValidateReleaseKeyPolicyV1JSON(raw) != nil {
		return nil, ErrPolicyInvalid
	}
	var policy Policy
	if err := decodeExact(raw, &policy); err != nil || validatePolicy(policy) != nil {
		return nil, ErrPolicyInvalid
	}
	canonical, err := canonicaljson.Marshal(policy)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrPolicyInvalid
	}
	return &policy, nil
}

func SignIndex(index []byte, privateKey ed25519.PrivateKey) ([]byte, []byte, error) {
	if _, err := ParseIndex(index); err != nil || !validPrivateKey(privateKey) {
		return nil, nil, ErrSigningFailed
	}
	return signPayload(IndexPayloadType, index, privateKey)
}

// PublicKeyID validates a canonical Ed25519 SPKI PEM and returns the canonical
// SHA-256 identity used in release DSSE signatures and policies.
func PublicKeyID(canonicalSPKI []byte) (string, error) {
	_, der, err := parseCanonicalSPKI(canonicalSPKI)
	if err != nil {
		return "", ErrSignatureInvalid
	}
	return digest(der), nil
}

func SignPolicy(policy Policy, authorityKey ed25519.PrivateKey) ([]byte, error) {
	envelopeRaw, _, _, err := SignPolicyWithAuthority(policy, authorityKey)
	return envelopeRaw, err
}

// SignPolicyWithAuthority returns the envelope and the exact canonical SPKI
// companion/key ID so authoring callers do not duplicate key normalization.
func SignPolicyWithAuthority(policy Policy, authorityKey ed25519.PrivateKey) ([]byte, []byte, string, error) {
	if validatePolicy(policy) != nil || !validPrivateKey(authorityKey) {
		return nil, nil, "", ErrSigningFailed
	}
	authorityDER, err := x509.MarshalPKIXPublicKey(authorityKey.Public())
	if err != nil {
		return nil, nil, "", ErrSigningFailed
	}
	authorityID := digest(authorityDER)
	for _, key := range policy.Keys {
		if key.KeyID == authorityID {
			return nil, nil, "", ErrSigningFailed
		}
	}
	payload, err := canonicaljson.Marshal(policy)
	if err != nil || len(payload) > MaxPolicyBytes {
		return nil, nil, "", ErrSigningFailed
	}
	envelopeRaw, authoritySPKI, err := signPayload(PolicyPayloadType, payload, authorityKey)
	if err != nil {
		return nil, nil, "", ErrSigningFailed
	}
	_, der, err := parseCanonicalSPKI(authoritySPKI)
	if err != nil {
		return nil, nil, "", ErrSigningFailed
	}
	return envelopeRaw, authoritySPKI, digest(der), nil
}

func signPayload(payloadType string, payload []byte, privateKey ed25519.PrivateKey) ([]byte, []byte, error) {
	public := privateKey.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, nil, ErrSigningFailed
	}
	spki := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	keyID := digest(der)
	env := envelope{PayloadType: payloadType, Payload: base64.StdEncoding.EncodeToString(payload), Signatures: []signature{{
		KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, pae(payloadType, payload))),
	}}}
	raw, err := canonicaljson.Marshal(env)
	if err != nil {
		return nil, nil, ErrSigningFailed
	}
	return raw, spki, nil
}

func VerifyPolicy(raw, authoritySPKI []byte, scope Scope, minimumGeneration uint64) (*VerifiedPolicy, error) {
	if !validScope(scope) || !validGeneration(minimumGeneration) {
		return nil, ErrPolicyInvalid
	}
	authority, der, err := parseCanonicalSPKI(authoritySPKI)
	if err != nil {
		return nil, ErrPolicyInvalid
	}
	payload, envDigest, err := authenticateEnvelope(raw, PolicyPayloadType, authority, digest(der), MaxPolicyEnvelopeBytes, MaxPolicyBytes)
	if err != nil {
		return nil, ErrPolicyInvalid
	}
	// Payload metadata is parsed only after the caller-rooted signature passed.
	policy, err := ParsePolicyPayload(payload)
	if err != nil || policy.Product != scope.Product || policy.Channel != scope.Channel || policy.Purpose != scope.Purpose || policy.Generation < minimumGeneration {
		return nil, ErrPolicyInvalid
	}
	statuses := make(map[string]string, len(policy.Keys))
	for _, key := range policy.Keys {
		if key.KeyID == digest(der) {
			return nil, ErrPolicyInvalid
		}
		statuses[key.KeyID] = key.Status
	}
	return &VerifiedPolicy{policy: *policy, statuses: statuses, authorityKeyID: digest(der), payloadDigest: digest(payload), envelopeDigest: envDigest}, nil
}

func VerifySignedIndex(indexRaw, envelopeRaw, signerSPKI []byte, policy *VerifiedPolicy, scope Scope, minimumReleaseGeneration uint64) (*VerifiedIndex, error) {
	authenticated, err := AuthenticateSignedIndex(indexRaw, envelopeRaw, signerSPKI, scope, minimumReleaseGeneration)
	if err != nil {
		return nil, err
	}
	return AuthorizeSignedIndex(authenticated, policy)
}

func AuthenticateSignedIndex(indexRaw, envelopeRaw, signerSPKI []byte, scope Scope, minimumReleaseGeneration uint64) (*AuthenticatedIndex, error) {
	if !validScope(scope) || !validGeneration(minimumReleaseGeneration) {
		return nil, ErrIndexInvalid
	}
	// Canonical index validation precedes signer/policy processing. The caller
	// floor is carried opaquely and enforced only after signer authorization.
	index, err := ParseIndex(indexRaw)
	if err != nil {
		return nil, ErrIndexInvalid
	}
	if index.Product != scope.Product || index.Channel != scope.Channel {
		return nil, ErrReleaseUntrusted
	}
	signer, der, err := parseCanonicalSPKI(signerSPKI)
	if err != nil {
		return nil, ErrSignatureInvalid
	}
	signerKeyID := digest(der)
	payload, envelopeDigest, err := authenticateEnvelope(envelopeRaw, IndexPayloadType, signer, signerKeyID, MaxEnvelopeBytes, MaxIndexBytes)
	if err != nil || !bytes.Equal(payload, indexRaw) {
		return nil, ErrSignatureInvalid
	}
	return &AuthenticatedIndex{index: cloneIndex(*index), indexRaw: bytes.Clone(indexRaw), indexDigest: digest(indexRaw), envelopeDigest: envelopeDigest, signerKeyID: signerKeyID, minimumReleaseGeneration: minimumReleaseGeneration}, nil
}

func AuthorizeSignedIndex(authenticated *AuthenticatedIndex, policy *VerifiedPolicy) (*VerifiedIndex, error) {
	if authenticated == nil || policy == nil || policy.Scope() != authenticated.Scope() {
		return nil, ErrReleaseUntrusted
	}
	signerKeyID := authenticated.signerKeyID
	if signerKeyID == policy.AuthorityKeyID() {
		return nil, ErrReleaseUntrusted
	}
	decision, err := policy.EvaluateSignerKeyID(signerKeyID)
	if err != nil || decision != TrustDecisionTrusted {
		return nil, ErrReleaseUntrusted
	}
	if authenticated.index.ReleaseGeneration < authenticated.minimumReleaseGeneration {
		return nil, ErrReleaseUntrusted
	}
	return &VerifiedIndex{index: cloneIndex(authenticated.index), indexRaw: bytes.Clone(authenticated.indexRaw), indexDigest: authenticated.indexDigest, envelopeDigest: authenticated.envelopeDigest, signerKeyID: signerKeyID}, nil
}

func CheckExpectedIndexDigest(index []byte, expected string) error {
	if len(index) == 0 || len(index) > MaxIndexBytes || !validDigest(expected) || digest(index) != expected {
		return ErrIndexInvalid
	}
	return nil
}

func ValidateExpectedIndexDigest(expected string) error {
	if !validDigest(expected) {
		return ErrIndexInvalid
	}
	return nil
}

func authenticateEnvelope(raw []byte, payloadType string, public ed25519.PublicKey, keyID string, maxEnvelope, maxPayload int) ([]byte, string, error) {
	if !validRawJSON(raw, maxEnvelope) {
		return nil, "", ErrSignatureInvalid
	}
	if payloadType == IndexPayloadType {
		if schemas.ValidateReleaseIndexEnvelopeV1JSON(raw) != nil {
			return nil, "", ErrSignatureInvalid
		}
	} else if payloadType == PolicyPayloadType {
		if schemas.ValidateReleaseKeyPolicyEnvelopeV1JSON(raw) != nil {
			return nil, "", ErrSignatureInvalid
		}
	} else if payloadType == AuthorityTransitionPayloadType {
		if schemas.ValidateReleaseAuthorityTransitionEnvelopeV1JSON(raw) != nil {
			return nil, "", ErrSignatureInvalid
		}
	} else {
		return nil, "", ErrSignatureInvalid
	}
	var env envelope
	if err := decodeExact(raw, &env); err != nil || env.PayloadType != payloadType || len(env.Signatures) != 1 || env.Signatures[0].KeyID != keyID {
		return nil, "", ErrSignatureInvalid
	}
	canonical, err := canonicaljson.Marshal(env)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, "", ErrSignatureInvalid
	}
	payload, err := decodeBase64(env.Payload, maxPayload)
	if err != nil {
		return nil, "", ErrSignatureInvalid
	}
	sig, err := decodeBase64(env.Signatures[0].Sig, ed25519.SignatureSize)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(public, pae(payloadType, payload), sig) {
		return nil, "", ErrSignatureInvalid
	}
	return payload, digest(raw), nil
}

func parseCanonicalSPKI(raw []byte) (ed25519.PublicKey, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxPublicKeyBytes {
		return nil, nil, ErrSignatureInvalid
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, nil, ErrSignatureInvalid
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, ErrSignatureInvalid
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, nil, ErrSignatureInvalid
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil || !bytes.Equal(der, block.Bytes) || !bytes.Equal(raw, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})) {
		return nil, nil, ErrSignatureInvalid
	}
	return public, der, nil
}

func validateIndex(index Index) error {
	if index.SchemaVersion != SchemaVersion || index.ArtifactType != IndexArtifactType || index.Product != Product || index.Channel != Channel || index.ProductVersion != ProductVersion || !validGeneration(index.ReleaseGeneration) || index.TrustBoundary != requiredTrustBoundary() || len(index.Files) < 1 || len(index.Files) > MaxFiles {
		return ErrIndexInvalid
	}
	previous := ""
	folded := make(map[string]struct{}, len(index.Files))
	hasSums := false
	var total uint64
	for i, file := range index.Files {
		if !portableBaseName(file.Path) || !validDigest(file.SHA256) || file.Size > MaxArtifactBytes || total > MaxArtifactSetBytes-file.Size || (i > 0 && previous >= file.Path) {
			return ErrIndexInvalid
		}
		total += file.Size
		fold := strings.ToLower(file.Path)
		if _, exists := folded[fold]; exists {
			return ErrIndexInvalid
		}
		folded[fold] = struct{}{}
		previous = file.Path
		hasSums = hasSums || file.Path == "SHA256SUMS"
	}
	if !hasSums {
		return ErrIndexInvalid
	}
	return nil
}

func validatePolicy(policy Policy) error {
	if policy.SchemaVersion != SchemaVersion || policy.Product != Product || policy.Channel != Channel || policy.Purpose != Purpose || !validGeneration(policy.Generation) || policy.KeyAlgorithm != "ed25519" || policy.KeyIDAlgorithm != "spki-sha256" || len(policy.Keys) < 1 || len(policy.Keys) > MaxPolicyKeys {
		return ErrPolicyInvalid
	}
	previous := ""
	for i, key := range policy.Keys {
		if !validDigest(key.KeyID) || (key.Status != "trusted" && key.Status != "revoked") || (i > 0 && previous >= key.KeyID) {
			return ErrPolicyInvalid
		}
		previous = key.KeyID
	}
	return nil
}

func requiredTrustBoundary() TrustBoundary {
	return TrustBoundary{Capability: "incomplete", FormalClaim: false, IdentityAttestation: "none", Overall: "inconclusive", TimeAttestation: "none"}
}

func validScope(scope Scope) bool                 { return scope == DefaultScope() }
func validGeneration(value uint64) bool           { return value > 0 && value <= MaxGeneration }
func validPrivateKey(key ed25519.PrivateKey) bool { return len(key) == ed25519.PrivateKeySize }
func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, c := range value[len("sha256:"):] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func portableBaseName(name string) bool {
	if name == "" || len(name) > 255 || name == "." || name == ".." || name != strings.TrimSpace(name) || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	if first := name[0]; !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')) {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("._-", c)) {
			return false
		}
	}
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CLOCK$" || base == "CONIN$" || base == "CONOUT$" {
		return false
	}
	return !(len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9')
}

func validRawJSON(raw []byte, maximum int) bool {
	return len(raw) > 0 && len(raw) <= maximum && !bytes.Contains(raw, []byte{'\r'}) && !bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf})
}

func decodeExact(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func decodeBase64(value string, maximum int) ([]byte, error) {
	if maximum < 0 || len(value) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, ErrSignatureInvalid
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) > maximum || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, ErrSignatureInvalid
	}
	return raw, nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func pae(payloadType string, payload []byte) []byte {
	prefix := "DSSEv1 " + strconv.Itoa(len([]byte(payloadType))) + " " + payloadType + " " + strconv.Itoa(len(payload)) + " "
	return append([]byte(prefix), payload...)
}

func cloneIndex(index Index) Index {
	index.Files = append([]FileEntry(nil), index.Files...)
	return index
}

func (s Scope) String() string { return fmt.Sprintf("%s/%s/%s", s.Product, s.Channel, s.Purpose) }
