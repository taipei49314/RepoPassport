package cli

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/taipei49314/RepoPassport/internal/acquisition"
	"github.com/taipei49314/RepoPassport/internal/domain"
	"github.com/taipei49314/RepoPassport/internal/manifest"
	"github.com/taipei49314/RepoPassport/internal/planner"
)

func resolveContainerHealthyJourneyPlan(
	ctx context.Context,
	manifestPath string,
) (domain.ResolvedPlan, error) {
	absoluteManifest, err := filepath.Abs(manifestPath)
	if err != nil {
		return domain.ResolvedPlan{}, err
	}
	document, err := manifest.Load(absoluteManifest)
	if err != nil {
		return domain.ResolvedPlan{}, err
	}
	provider := acquisition.NewLocalProvider()
	resolved, err := provider.Resolve(ctx, domain.SourceRef{
		Kind:  "local",
		Value: filepath.Dir(absoluteManifest),
	})
	if err != nil {
		return domain.ResolvedPlan{}, err
	}
	snapshot, err := provider.Fetch(ctx, resolved)
	if err != nil {
		return domain.ResolvedPlan{}, err
	}
	return planner.Resolve(document, snapshot, "quickstart")
}

func TestContainerHealthyJourneyPlanResolverMatchesCLI(t *testing.T) {
	t.Parallel()
	fixtures := []string{
		"healthy-node-cli",
		"healthy-python-cli",
		"healthy-node-http",
		"healthy-python-http",
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture, func(t *testing.T) {
			t.Parallel()
			manifestPath, err := filepath.Abs(filepath.Join(
				"..", "..", "testdata", "fixtures", "healthy", fixture,
				"repo-passport.yml",
			))
			if err != nil {
				t.Fatalf("resolve fixture manifest: %v", err)
			}
			got, err := resolveContainerHealthyJourneyPlan(
				context.Background(),
				manifestPath,
			)
			if err != nil {
				t.Fatalf("independently resolve healthy journey plan: %v", err)
			}
			want, _, _, err := loadPlan(
				context.Background(),
				manifestPath,
				"quickstart",
			)
			if err != nil {
				t.Fatalf("load CLI healthy journey plan: %v", err)
			}
			if got.PlanDigest != want.PlanDigest ||
				got.Source != want.Source ||
				got.BaseImageReference != want.BaseImageReference ||
				got.BaseImageDigest != want.BaseImageDigest ||
				got.RepeatCount != want.RepeatCount ||
				got.SuccessThreshold != want.SuccessThreshold {
				t.Fatalf(
					"independent healthy plan differs from CLI plan: got %#v want %#v",
					got,
					want,
				)
			}
		})
	}
}
