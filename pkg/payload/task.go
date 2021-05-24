package payload

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"

	manifest "github.com/openshift/library-go/pkg/manifest"
)

var (
	metricPayloadErrors = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cluster_operator_payload_errors",
		Help: "Report the number of errors encountered applying the payload.",
	}, []string{"version"})

	clusterOperatorUpdateStartTimes = struct {
		lock sync.RWMutex
		m    map[string]time.Time
	}{m: make(map[string]time.Time)}
)

func init() {
	prometheus.MustRegister(
		metricPayloadErrors,
	)
}

// InitCOUpdateStartTimes creates the clusterOperatorUpdateStartTimes map thereby resulting
// in an empty map.
func InitCOUpdateStartTimes() {
	clusterOperatorUpdateStartTimes.lock.Lock()
	clusterOperatorUpdateStartTimes.m = make(map[string]time.Time)
	clusterOperatorUpdateStartTimes.lock.Unlock()
}

// COUpdateStartTimesEnsureName adds name to clusterOperatorUpdateStartTimes map and sets to
// current time if name does not already exist in map.
func COUpdateStartTimesEnsureName(name string) {
	clusterOperatorUpdateStartTimes.lock.Lock()
	if _, ok := clusterOperatorUpdateStartTimes.m[name]; !ok {
		clusterOperatorUpdateStartTimes.m[name] = time.Now()
	}
	clusterOperatorUpdateStartTimes.lock.Unlock()
}

// COUpdateStartTimesGet returns name's value from clusterOperatorUpdateStartTimes map.
func COUpdateStartTimesGet(name string) time.Time {
	clusterOperatorUpdateStartTimes.lock.Lock()
	defer clusterOperatorUpdateStartTimes.lock.Unlock()
	return clusterOperatorUpdateStartTimes.m[name]
}

// ResourceBuilder abstracts how a manifest is created on the server. Introduced for testing.
type ResourceBuilder interface {
	Apply(context.Context, *manifest.Manifest, State) error
}

type Task struct {
	Index    int
	Total    int
	Manifest *manifest.Manifest
	Requeued int
	Backoff  wait.Backoff
}

func (st *Task) Copy() *Task {
	return &Task{
		Index:    st.Index,
		Total:    st.Total,
		Manifest: st.Manifest,
		Requeued: st.Requeued,
	}
}

func (st *Task) String() string {
	name := st.Manifest.Obj.GetName()
	if len(name) == 0 {
		name = st.Manifest.OriginalFilename
	}
	ns := st.Manifest.Obj.GetNamespace()
	if len(ns) == 0 {
		return fmt.Sprintf("%s %q (%d of %d)", strings.ToLower(st.Manifest.GVK.Kind), name, st.Index, st.Total)
	}
	return fmt.Sprintf("%s \"%s/%s\" (%d of %d)", strings.ToLower(st.Manifest.GVK.Kind), ns, name, st.Index, st.Total)
}

// Run attempts to create the provided object until it succeeds or context is cancelled. It returns the
// last error if context is cancelled.
func (st *Task) Run(ctx context.Context, version string, builder ResourceBuilder, state State) error {
	var lastErr error
	backoff := st.Backoff
	err := wait.ExponentialBackoffWithContext(ctx, backoff, func() (done bool, err error) {
		err = builder.Apply(ctx, st.Manifest, state)
		if err == nil {
			return true, nil
		}
		if updateErr, ok := lastErr.(*UpdateError); ok {
			updateErr.Task = st.Copy()
			return false, updateErr // failing fast for UpdateError
		}

		lastErr = err
		utilruntime.HandleError(errors.Wrapf(err, "error running apply for %s", st))
		metricPayloadErrors.WithLabelValues(version).Inc()
		return false, nil
	})
	if lastErr != nil {
		err = lastErr
	}
	if err == nil {
		return nil
	}
	if _, ok := err.(*UpdateError); ok {
		return err
	}
	reason, cause := reasonForPayloadSyncError(err)
	if len(cause) > 0 {
		cause = ": " + cause
	}
	return &UpdateError{
		Nested:  err,
		Reason:  reason,
		Message: fmt.Sprintf("Could not update %s%s", st, cause),
		Task:    st.Copy(),
	}
}

// UpdateEffectType defines the effect an update error has on the overall update state.
type UpdateEffectType string

const (
	// UpdateEffectNone defines an error as having no affect on the update state.
	UpdateEffectNone UpdateEffectType = "None"

	// UpdateEffectFail defines an error as indicating the update is failing.
	UpdateEffectFail UpdateEffectType = "Fail"

	// UpdateEffectFailAfterInterval defines an error as one which indicates the update
	// is failing if the error continues for a defined interval.
	UpdateEffectFailAfterInterval UpdateEffectType = "FailAfterInterval"
)

// UpdateError is a wrapper for errors that occur during a payload sync.
type UpdateError struct {
	Nested       error
	UpdateEffect UpdateEffectType
	Reason       string
	Message      string
	Name         string

	Task *Task
}

func (e *UpdateError) Error() string {
	return e.Message
}

func (e *UpdateError) Cause() error {
	return e.Nested
}

// reasonForPayloadSyncError provides a succint explanation of a known error type for use in a human readable
// message during update. Since all objects in the image should be successfully applied, messages
// should direct the reader (likely a cluster administrator) to a possible cause in their own config.
func reasonForPayloadSyncError(err error) (string, string) {
	err = errors.Cause(err)
	switch {
	case apierrors.IsNotFound(err), apierrors.IsAlreadyExists(err):
		return "UpdatePayloadResourceNotFound", "resource may have been deleted"
	case apierrors.IsConflict(err):
		return "UpdatePayloadResourceConflict", "someone else is updating this resource"
	case apierrors.IsTimeout(err), apierrors.IsServiceUnavailable(err), apierrors.IsUnexpectedServerError(err):
		return "UpdatePayloadClusterDown", "the server is down or not responding"
	case apierrors.IsInternalError(err):
		return "UpdatePayloadClusterError", "the server is reporting an internal error"
	case apierrors.IsInvalid(err):
		return "UpdatePayloadResourceInvalid", "the object is invalid, possibly due to local cluster configuration"
	case apierrors.IsUnauthorized(err):
		return "UpdatePayloadClusterUnauthorized", "could not authenticate to the server"
	case apierrors.IsForbidden(err):
		return "UpdatePayloadResourceForbidden", "the server has forbidden updates to this resource"
	case apierrors.IsServerTimeout(err), apierrors.IsTooManyRequests(err):
		return "UpdatePayloadClusterOverloaded", "the server is overloaded and is not accepting updates"
	case meta.IsNoMatchError(err):
		return "UpdatePayloadResourceTypeMissing", "the server does not recognize this resource, check extension API servers"
	default:
		return "UpdatePayloadFailed", ""
	}
}

func SummaryForReason(reason, name string) string {
	switch reason {

	// likely temporary errors
	case "UpdatePayloadResourceNotFound", "UpdatePayloadResourceConflict":
		return "some resources could not be updated"
	case "UpdatePayloadClusterDown":
		return "the control plane is down or not responding"
	case "UpdatePayloadClusterError":
		return "the control plane is reporting an internal error"
	case "UpdatePayloadClusterOverloaded":
		return "the control plane is overloaded and is not accepting updates"
	case "UpdatePayloadClusterUnauthorized":
		return "could not authenticate to the server"
	case "UpdatePayloadRetrievalFailed":
		return "could not download the update"

	// likely a policy or other configuration error due to end user action
	case "UpdatePayloadResourceForbidden":
		return "the server is rejecting updates"

	// the image may not be correct, or the cluster may be in an unexpected
	// state
	case "UpdatePayloadResourceTypeMissing":
		return "a required extension is not available to update"
	case "UpdatePayloadResourceInvalid":
		return "some cluster configuration is invalid"
	case "UpdatePayloadIntegrity":
		return "the contents of the update are invalid"

	case "ImageVerificationFailed":
		return "the image may not be safe to use"

	case "UpgradePreconditionCheckFailed":
		return "it may not be safe to apply this update"

	case "ClusterOperatorDegraded":
		if len(name) > 0 {
			return fmt.Sprintf("the cluster operator %s is degraded", name)
		}
		return "a cluster operator is degraded"
	case "ClusterOperatorNotAvailable":
		if len(name) > 0 {
			return fmt.Sprintf("the cluster operator %s has not yet successfully rolled out", name)
		}
		return "a cluster operator has not yet rolled out"
	case "ClusterOperatorsNotAvailable":
		return "some cluster operators have not yet rolled out"
	case "WorkloadNotAvailable":
		if len(name) > 0 {
			return fmt.Sprintf("the workload %s has not yet successfully rolled out", name)
		}
		return "a workload has not yet rolled out"
	case "WorkloadNotProgressing":
		if len(name) > 0 {
			return fmt.Sprintf("the workload %s cannot roll out", name)
		}
		return "a workload cannot roll out"
	}

	if strings.HasPrefix(reason, "UpdatePayload") {
		return "the update could not be applied"
	}

	if len(name) > 0 {
		return fmt.Sprintf("%s has an unknown error: %s", name, reason)
	}
	return fmt.Sprintf("an unknown error has occurred: %s", reason)
}
