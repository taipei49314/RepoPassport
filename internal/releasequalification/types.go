package releasequalification

import "github.com/taipei49314/RepoPassport/internal/buildidentity"

// ArtifactSpec identifies one required executable and its exact build
// identity. Paths are private qualification inputs and are never copied into
// the potentially public qualification log.
type ArtifactSpec struct {
	ID       string
	Path     string
	Identity buildidentity.BuildIdentity
}

// ArtifactReport binds an executable identity result to one stable byte
// snapshot. Results contains failures only; an accepted artifact has an empty
// Results slice.
type ArtifactReport struct {
	ID      string
	Size    int64
	SHA256  string
	Results []buildidentity.Result
}

// KitSpec identifies one required portable verifier kit and the standalone
// verifier whose exact bytes the kit must contain.
type KitSpec struct {
	ID                     string
	Path                   string
	TargetOS               string
	StandaloneVerifierPath string
}

// KitReport binds a validated portable kit to the verifier independently
// inspected from inside it.
type KitReport struct {
	ID               string
	Size             int64
	SHA256           string
	EmbeddedVerifier ArtifactReport
}

// LogRecord is the complete allowlist for potentially public qualification
// logs. In particular it deliberately contains no local filesystem path.
type LogRecord struct {
	ID       string `json:"id"`
	SHA256   string `json:"sha256"`
	Revision string `json:"revision"`
	Tree     string `json:"tree"`
}

// QualificationReport retains the frozen required set and all deterministic
// build-identity failures, even when qualification blocks publication.
type QualificationReport struct {
	Artifacts         []ArtifactReport
	Kits              []KitReport
	Results           []buildidentity.Result
	FirstFailure      *buildidentity.Result
	Log               []LogRecord
	StructuralFailure bool
}
