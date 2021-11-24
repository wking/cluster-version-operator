package clusterversion

import (
	"context"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/cluster-version-operator/pkg/payload/precondition"
)

func TestRecommendedUpdate(t *testing.T) {
	ctx := context.Background()

	targetVersion := "4.3.2"
	tests := []struct {
		name               string
		channel            string
		availableUpdates   []configv1.Release
		conditionalUpdates []configv1.ConditionalUpdate
		conditions         []configv1.ClusterOperatorStatusCondition
		expected           string
	}{
		{
			name:             "recommended",
			availableUpdates: []configv1.Release{{Version: targetVersion}},
		},
		{
			name: "no relevant data",
		},
		{
			name: "Recommended=True",
			conditionalUpdates: []configv1.ConditionalUpdate{{
				Release: configv1.Release{Version: targetVersion},
				Conditions: []metav1.Condition{{
					Type:    "Recommended",
					Status:  metav1.ConditionTrue,
					Reason:  "RecommendedReason",
					Message: "For some reason, this update is recommended.",
				}},
			}},
		},
		{
			name: "Recommended=False",
			conditionalUpdates: []configv1.ConditionalUpdate{{
				Release: configv1.Release{Version: targetVersion},
				Conditions: []metav1.Condition{{
					Type:    "Recommended",
					Status:  metav1.ConditionFalse,
					Reason:  "FalseReason",
					Message: "For some reason, this update is not recommended.",
				}},
			}},
			expected: "Update from 4.3.0 to 4.3.2 is not recommended:\n\nFor some reason, this update is not recommended.",
		},
		{
			name: "Recommended=Unknown",
			conditionalUpdates: []configv1.ConditionalUpdate{{
				Release: configv1.Release{Version: targetVersion},
				Conditions: []metav1.Condition{{
					Type:    "Recommended",
					Status:  metav1.ConditionUnknown,
					Reason:  "UnknownReason",
					Message: "For some reason, we cannot decide if this update is recommended.",
				}},
			}},
		},
		{
			name: "RetrievedUpdates=False",
			conditions: []configv1.ClusterOperatorStatusCondition{{
				Type:    configv1.RetrievedUpdates,
				Status:  configv1.ConditionFalse,
				Reason:  "FalseReason",
				Message: "For some reason, we cannot retrieve update recommendations.",
			}},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			clusterVersion := &configv1.ClusterVersion{
				Spec: configv1.ClusterVersionSpec{Channel: testCase.channel},
				Status: configv1.ClusterVersionStatus{
					Desired:            configv1.Release{Version: "4.3.0"},
					AvailableUpdates:   testCase.availableUpdates,
					ConditionalUpdates: testCase.conditionalUpdates,
					Conditions:         testCase.conditions,
				},
			}
			instance := NewRecommendedUpdate()
			err := instance.Run(ctx, precondition.ReleaseContext{DesiredVersion: targetVersion}, clusterVersion)
			switch {
			case err != nil && len(testCase.expected) == 0:
				t.Error(err)
			case err != nil && err.Error() == testCase.expected:
			case err != nil && err.Error() != testCase.expected:
				t.Errorf("got %q, but expected %q", err, testCase.expected)
			case err == nil && len(testCase.expected) == 0:
			case err == nil && len(testCase.expected) != 0:
				t.Errorf("got %q, but expected %q", err, testCase.expected)
			}

		})
	}
}
