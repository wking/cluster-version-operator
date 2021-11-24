package precondition

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/openshift/cluster-version-operator/pkg/payload"
)

func TestSummarize(t *testing.T) {
	tests := []struct {
		name     string
		input    []error
		expWarn  error
		expBlock error
	}{{
		name: "nil",
		input: nil,
	}, {
		name:  "empty slice", 
		input: []error{},
	}, {
		name:  "unrecognized error type",
		input: []error{fmt.Errorf("random error")},
		expBlock: &payload.UpdateError{
			Nested:  fmt.Errorf("random error"),
			Reason:  "UpgradePreconditionCheckFailed",
			Message: "random error",
			Name:    "PreconditionCheck",
		},
	}, {
		name:  "single feature gate failure",
		input: []error{&Error{
			Nested:  nil,
			Reason:  "NotAllowedFeatureGateSet",
			Message: "Feature Gate random is set for the cluster. This Feature Gate turns on features that are not part of the normal supported platform.",
			Name:    "FeatureGate",
		}},
		expBlock: &payload.UpdateError{
			Nested:  &Error{
				Nested:  nil,
				Reason:  "NotAllowedFeatureGateSet",
				Message: "Feature Gate random is set for the cluster. This Feature Gate turns on features that are not part of the normal supported platform.",
				Name:    "FeatureGate",
			},
			Reason:  "NotAllowedFeatureGateSet",
			Message: `Feature Gate random is set for the cluster. This Feature Gate turns on features that are not part of the normal supported platform.`,
			Name:    "FeatureGate",
		},
	}, {
		name:  "multiple, unrecognized error types",
		input: []error{fmt.Errorf("random error 1"), fmt.Errorf("random error 2")},
		expBlock: &payload.UpdateError{
			Nested:  utilerrors.NewAggregate([]error{fmt.Errorf("random error 1"), fmt.Errorf("random error 2")}),
			Reason:  "UpgradePreconditionCheckFailed",
			Message: `Multiple precondition checks failed:
* random error 1
* random error 2`,
			Name:    "PreconditionCheck",
		},
	}, {
		name:  []...
		input: []error{&Error{
			Nested:  nil,
			Reason:  "NotAllowedFeatureGateSet",
			Message: "Feature Gate random is set for the cluster. This Feature Gate turns on features that are not part of the normal supported platform.",
			Name:    "FeatureGate",
		}, &Error{
			Nested:  nil,
			Reason:  "NotAllowedFeatureGateSet",
			Message: "Feature Gate random-2 is set for the cluster. This Feature Gate turns on features that are not part of the normal supported platform.",
			Name:    "FeatureGate",
		}},
		exp: `Multiple precondition checks failed:
* Precondition "FeatureGate" failed because of "NotAllowedFeatureGateSet": Feature Gate random is set for the cluster. This Feature Gate turns on features that are not part of the normal supported platform.
* Precondition "FeatureGate" failed because of "NotAllowedFeatureGateSet": Feature Gate random-2 is set for the cluster. This Feature Gate turns on features that are not part of the normal supported platform.`,
/*
	}, {
		input: []error{
			fmt.Errorf("random error"),
			&Error{
				Nested:  nil,
				Reason:  "NotAllowedFeatureGateSet",
				Message: "Feature Gate random is set for the cluster. This Feature Gate turns on features that are not part of the normal supported platform.",
				Name:    "FeatureGate",
			}},
		exp: `Multiple precondition checks failed:
* random error
* Precondition "FeatureGate" failed because of "NotAllowedFeatureGateSet": Feature Gate random is set for the cluster. This Feature Gate turns on features that are not part of the normal supported platform.`,
*/
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			warn, block := Summarize(test.input)
			if !reflect.DeepEqual(warn, test.expWarn) {
				t.Errorf("expected warning: %s got: %s", spew.Sdump(test.expWarn), spew.Sdump(warn))
			}
			if !reflect.DeepEqual(block, test.expBlock) {
				t.Errorf("expected block: %s got: %s", spew.Sdump(test.expBlock), spew.Sdump(block))
			}
		})
	}
}
