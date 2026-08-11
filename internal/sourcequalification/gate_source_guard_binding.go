package sourcequalification

import "context"

func (guard *qualificationLaneSourceGuard) BindApplications(
	ctx context.Context,
	applications map[string]string,
) (gateApplicationBinding, error) {
	return guard.inner.BindApplications(ctx, applications)
}
