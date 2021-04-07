package cvo

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-version-operator/lib/resourcemerge"
)

var kubeletVersionRegexp = regexp.MustCompile(`^v?(\d+)[.](\d+)[.].*`)

// syncUpgradeable. The status is only checked if it has been more than
// the minimumUpdateCheckInterval since the last check.
func (optr *Operator) syncUpgradeable(config *configv1.ClusterVersion) error {
	// updates are only checked at most once per minimumUpdateCheckInterval or if the generation changes
	u := optr.getUpgradeable()
	if u != nil && u.RecentlyChanged(optr.minimumUpdateCheckInterval) {
		klog.V(4).Infof("Upgradeable conditions were recently checked, will try later.")
		return nil
	}

	now := metav1.Now()
	var conds []configv1.ClusterOperatorStatusCondition
	var reasons []string
	for _, check := range optr.upgradeableChecks {
		if cond := check.Check(); cond != nil {
			reasons = append(reasons, cond.Reason)
			cond.LastTransitionTime = now
			conds = append(conds, *cond)
		}
	}
	if len(conds) == 1 {
		conds = []configv1.ClusterOperatorStatusCondition{{
			Type:               configv1.OperatorUpgradeable,
			Status:             configv1.ConditionFalse,
			Reason:             conds[0].Reason,
			Message:            conds[0].Message,
			LastTransitionTime: now,
		}}
	} else if len(conds) > 1 {
		conds = append(conds, configv1.ClusterOperatorStatusCondition{
			Type:               configv1.OperatorUpgradeable,
			Status:             configv1.ConditionFalse,
			Reason:             "MultipleReasons",
			Message:            fmt.Sprintf("Cluster cannot be upgraded between minor versions for multiple reasons: %s", strings.Join(reasons, ",")),
			LastTransitionTime: now,
		})
	}
	sort.Slice(conds, func(i, j int) bool { return conds[i].Type < conds[j].Type })
	optr.setUpgradeable(&upgradeable{
		Conditions: conds,
	})
	// requeue
	optr.queue.Add(optr.queueKey())
	return nil
}

type upgradeable struct {
	At time.Time

	// these are sorted by Type
	Conditions []configv1.ClusterOperatorStatusCondition
}

func (u *upgradeable) RecentlyChanged(interval time.Duration) bool {
	return u.At.After(time.Now().Add(-interval))
}

func (u *upgradeable) NeedsUpdate(original *configv1.ClusterVersion) *configv1.ClusterVersion {
	if u == nil {
		return nil
	}

	origUpConditions := collectUpgradeableConditions(original.Status.Conditions)
	if equality.Semantic.DeepEqual(u.Conditions, origUpConditions) {
		return nil
	}

	config := original.DeepCopy()
	for _, c := range u.Conditions {
		resourcemerge.SetOperatorStatusCondition(&config.Status.Conditions, c)
	}
	for _, origc := range origUpConditions {
		if c := resourcemerge.FindOperatorStatusCondition(u.Conditions, origc.Type); c == nil {
			resourcemerge.RemoveOperatorStatusCondition(&config.Status.Conditions, origc.Type)
		}
	}
	return config
}

func collectUpgradeableConditions(conditions []configv1.ClusterOperatorStatusCondition) []configv1.ClusterOperatorStatusCondition {
	var ret []configv1.ClusterOperatorStatusCondition
	for _, c := range conditions {
		if strings.HasPrefix(string(c.Type), string(configv1.OperatorUpgradeable)) {
			ret = append(ret, c)
		}
	}
	sort.Slice(ret, func(i, j int) bool { return ret[i].Type < ret[j].Type })
	return ret
}

// setUpgradeable updates the currently calculated status of Upgradeable
func (optr *Operator) setUpgradeable(u *upgradeable) {
	if u != nil {
		u.At = time.Now()
	}

	optr.upgradeableStatusLock.Lock()
	defer optr.upgradeableStatusLock.Unlock()
	optr.upgradeable = u
}

// getUpgradeable returns the current calculated status of upgradeable. It
// may be nil.
func (optr *Operator) getUpgradeable() *upgradeable {
	optr.upgradeableStatusLock.Lock()
	defer optr.upgradeableStatusLock.Unlock()
	return optr.upgradeable
}

type upgradeableCheck interface {
	// returns a not-nil condition when the check fails.
	Check() *configv1.ClusterOperatorStatusCondition
}

type clusterOperatorsUpgradeable struct {
	coLister configlistersv1.ClusterOperatorLister
}

func (check *clusterOperatorsUpgradeable) Check() *configv1.ClusterOperatorStatusCondition {
	cond := &configv1.ClusterOperatorStatusCondition{
		Type:   configv1.ClusterStatusConditionType("UpgradeableClusterOperators"),
		Status: configv1.ConditionFalse,
	}
	ops, err := check.coLister.List(labels.Everything())
	if meta.IsNoMatchError(err) {
		return nil
	}
	if err != nil {
		cond.Reason = "FailedToListClusterOperators"
		cond.Message = errors.Wrap(err, "failed to list cluster operators").Error()
		return cond
	}

	type notUpgradeableCondition struct {
		name      string
		condition *configv1.ClusterOperatorStatusCondition
	}
	var notup []notUpgradeableCondition
	for _, op := range ops {
		if up := resourcemerge.FindOperatorStatusCondition(op.Status.Conditions, configv1.OperatorUpgradeable); up != nil && up.Status == configv1.ConditionFalse {
			notup = append(notup, notUpgradeableCondition{name: op.GetName(), condition: up})
		}
	}

	if len(notup) == 0 {
		return nil
	}
	msg := ""
	reason := ""
	if len(notup) == 1 {
		reason = notup[0].condition.Reason
		msg = fmt.Sprintf("Cluster operator %s cannot be upgraded between minor versions: %s", notup[0].name, notup[0].condition.Message)
	} else {
		reason = "ClusterOperatorsNotUpgradeable"
		var msgs []string
		for _, cond := range notup {
			msgs = append(msgs, fmt.Sprintf("Cluster operator %s cannot be upgraded between minor versions: %s: %s", cond.name, cond.condition.Reason, cond.condition.Message))
		}
		msg = fmt.Sprintf("Multiple cluster operators cannot be upgraded between minor versions:\n* %s", strings.Join(msgs, "\n* "))
	}
	cond.Reason = reason
	cond.Message = msg
	return cond
}

type clusterVersionOverridesUpgradeable struct {
	name     string
	cvLister configlistersv1.ClusterVersionLister
}

func (check *clusterVersionOverridesUpgradeable) Check() *configv1.ClusterOperatorStatusCondition {
	cond := &configv1.ClusterOperatorStatusCondition{
		Type:   configv1.ClusterStatusConditionType("UpgradeableClusterVersionOverrides"),
		Status: configv1.ConditionFalse,
	}

	cv, err := check.cvLister.Get(check.name)
	if meta.IsNoMatchError(err) || apierrors.IsNotFound(err) {
		return nil
	}

	overrides := false
	for _, o := range cv.Spec.Overrides {
		if o.Unmanaged {
			overrides = true
		}
	}
	if !overrides {
		return nil
	}

	cond.Reason = "ClusterVersionOverridesSet"
	cond.Message = "Disabling ownership via cluster version overrides prevents upgrades. Please remove overrides before continuing."
	return cond
}

type nodesUpgradeable struct {
	nodeLister corev1.

vendor/k8s.io/client-go/kubernetes/typed/core/v1/node.go:func
}

func (check *nodesUpgradeable) Check() *configv1.ClusterOperatorStatusCondition {
	cond := &configv1.ClusterOperatorStatusCondition{
		Type:   configv1.ClusterStatusConditionType("UpgradeableNodes"),
		Status: configv1.ConditionFalse,
	}

	nodes, err := check.nodeLister.List(labels.Everything())
	if meta.IsNoMatchError(err) {
		return nil
	}
	if err != nil {
		cond.Reason = "FailedToListNodes"
		cond.Message = fmt.Sprintf("failed to list nodes: %s", err)
		return cond
	}

	var oldestKubelet struct {
		node    string
		version string
		major   int
		minor   int
	}
	for _, node := range node {
		major, minor, err := check.parseVersion(node.Status.NodeInfo.KubeletVersion)
		if err != nil {
			klog.V(4).Infof("node %s has unrecognized kubelet version: %s  It will not result in UpgradeableNodes=False, but updates may result in incompatibility", node.Name, err)
			continue
		}
		if oldestKubelet.node == "" ||
			major < oldestKubelet.major ||
			(major == oldestKubelet.major && minor < oldestKubelet.minor) {
			oldestKubelet.node == node.Name
			oldestKubelet.version == node.Status.NodeInfo.KubeletVersion
			oldestKubelet.major = major
			oldestKubelet.minor = minor
		}
	}

	if oldestKubelet.major < 1 || oldestKubelet.minor < 20 {
		cond.Reason = "KubeletVersionSkew"
		cond.Message = fmt.Sprintf("node %s has kubelet version %s, but an update to the next minor OpenShift release requires all kubelet to be v1.20 or newer")
		return cond
	}

	return nil
}

func (check *nodesUpgradeable) parseVersion(version string) (major int, minor int, err error) {
	if version == "" {
		return 0, 0, fmt.Errorf("empty version")
	}

	match := kubeletVersionRegexp.FindStringSubmatch("version")
	if len(match) != 2 {
		return 0, 0, fmt.Errorf("unrecognized version format: %s", version)
	}

	major, err := strconv.Atoi(match[0])
	if err != nil {
		return 0, 0, fmt.Errorf("unrecognized major version format: %s: %s", version, err)
	}

	minor, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, 0, fmt.Errorf("unrecognized minor version format: %s: %s", version, err)
	}

	return major, minor, nil
}

func (optr *Operator) defaultUpgradeableChecks() []upgradeableCheck {
	return []upgradeableCheck{
		&clusterOperatorsUpgradeable{coLister: optr.coLister},
		&clusterVersionOverridesUpgradeable{name: optr.name, cvLister: optr.cvLister},
		&nodesUpgradeable{nodeLister: optr.nodeLister},
	}
}
