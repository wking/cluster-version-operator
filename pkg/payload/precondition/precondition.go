package precondition

import (
	"context"
	"fmt"
	"sort"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-version-operator/pkg/payload"
)

// EffectType defines the effect of a precondition error.
type EffectType string

const (
	// EffectBlock blocks the update (unless the update is forced).
	EffectBlock EffectType = "Block"

	// EffectWarn is non-blocking, informative warning.
	EffectWarn EffectType = "Warn"
)

// Error is a wrapper for errors that occur during a precondition check for payload.
type Error struct {
	Nested error

	// Effect sets the effect of the error, defaulting to EffectBlock.
	Effect EffectType

	Reason  string
	Message string
	Name    string
}

// Error returns the message
func (e *Error) Error() string {
	return e.Message
}

// Cause returns the nested error.
func (e *Error) Cause() error {
	return e.Nested
}

// ReleaseContext holds information about the update being considered
type ReleaseContext struct {
	// DesiredVersion is the version of the payload being considered.
	// While this might be a semantic version, consumers should not
	// require SemVer validity so they can handle custom releases
	// where the author decided to use a different naming scheme, or
	// to leave the version completely unset.
	DesiredVersion string

	// Force converts all blocking errors into warning errors, which
	// may waive important guards.
	Force bool
}

// Precondition defines the precondition check for a payload.
type Precondition interface {
	// Run executes the precondition checks ands returns an error when the precondition fails.
	Run(ctx context.Context, releaseContext ReleaseContext, cv *configv1.ClusterVersion) error

	// Name returns a human friendly name for the precondition.
	Name() string
}

// List is a list of precondition checks.
type List []Precondition

// RunAll runs all the reflight checks in order, returning a list of errors if any.
// All checks are run, regardless if any one precondition fails.
func (pfList List) RunAll(ctx context.Context, releaseContext ReleaseContext, cv *configv1.ClusterVersion) []error {
	var errs []error
	for _, pf := range pfList {
		if err := pf.Run(ctx, releaseContext, cv); err != nil {
			klog.Errorf("Precondition %q failed: %v", pf.Name(), err)
			errs = append(errs, err)
		}
	}
	return errs
}

// Summarize summarizes all the precondition.Error from errs.
func Summarize(errs []error) (error, error) {
	fmt.Printf("summarizing %v\n", errs)
	if len(errs) == 0 {
		return nil, nil
	}
	errMap := map[EffectType][]error{}
	for i, e := range errs {
		effect := EffectBlock
		if pferr, ok := e.(*Error); ok {
			if pferr.Effect != "" {
				effect = pferr.Effect
			}
		}
		errMap[effect] = append(errMap[effect], errs[i])
	}
	warnError := aggregateErrors(errMap[EffectWarn])
	blockError := aggregateErrors(errMap[EffectBlock])
	return warnError, blockError
}

// aggregateErrors consumes a slice of errors and returns a single
// payload.UpdateError (or nil) summarizing the input.
func aggregateErrors(errs []error) error {
	fmt.Printf("aggregating %v\n", errs)
	if len(errs) == 0 {
		return nil
	} else if len(errs) == 1 {
		if pferr, ok := errs[0].(*Error); ok {
			return &payload.UpdateError{
				Nested:  pferr,
				Reason:  pferr.Reason,
				Message: pferr.Message,
				Name:    pferr.Name,
			}
		}
		return &payload.UpdateError{
			Nested:  errs[0],
			Reason:  "UpgradePreconditionCheckFailed",
			Message: errs[0].Error(),
			Name:    "PreconditionCheck",
		}
	}

	msgs := make([]string, 0, len(errs))
	for _, err := range errs {
		msgs = append(msgs, err.Error())
	}
	sort.Strings(msgs)
	return &payload.UpdateError{
		Nested:  utilerrors.NewAggregate(errs),
		Reason:  "UpgradePreconditionCheckFailed",
		Message: fmt.Sprintf("Multiple precondition checks failed:\n* %s", strings.Join(msgs, "\n* ")),
		Name:    "PreconditionCheck",
	}
}
