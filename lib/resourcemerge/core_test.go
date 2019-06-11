package resourcemerge

import (
	"testing"

	"github.com/ghodss/yaml"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/utils/pointer"
)

func TestEnsurePodSpec(t *testing.T) {
	tests := []struct {
		name     string
		existing corev1.PodSpec
		input    corev1.PodSpec

		expectedModified bool
		expected         corev1.PodSpec
	}{
		{
			name:     "empty inputs",
			existing: corev1.PodSpec{},
			input:    corev1.PodSpec{},

			expectedModified: false,
			expected:         corev1.PodSpec{},
		},
		{
			name: "remove regular containers from existing",
			existing: corev1.PodSpec{
				Containers: []corev1.Container{
					corev1.Container{Name: "test"}}},
			input: corev1.PodSpec{},

			expectedModified: true,
			expected:         corev1.PodSpec{},
		},
		{
			name: "remove regular and init containers from existing",
			existing: corev1.PodSpec{
				InitContainers: []corev1.Container{
					corev1.Container{Name: "test-init"}},
				Containers: []corev1.Container{
					corev1.Container{Name: "test"}}},
			input: corev1.PodSpec{},

			expectedModified: true,
			expected:         corev1.PodSpec{},
		},
		{
			name: "remove init containers from existing",
			existing: corev1.PodSpec{
				InitContainers: []corev1.Container{
					corev1.Container{Name: "test-init"}}},
			input: corev1.PodSpec{},

			expectedModified: true,
			expected:         corev1.PodSpec{},
		},
		{
			name: "append regular and init containers",
			existing: corev1.PodSpec{
				InitContainers: []corev1.Container{
					corev1.Container{Name: "test-init-a"}},
				Containers: []corev1.Container{
					corev1.Container{Name: "test-a"}}},
			input: corev1.PodSpec{
				InitContainers: []corev1.Container{
					corev1.Container{Name: "test-init-a"},
					corev1.Container{Name: "test-init-b"},
				},
				Containers: []corev1.Container{
					corev1.Container{Name: "test-a"},
					corev1.Container{Name: "test-b"},
				},
			},

			expectedModified: true,
			expected: corev1.PodSpec{
				InitContainers: []corev1.Container{
					corev1.Container{Name: "test-init-a"},
					corev1.Container{Name: "test-init-b"},
				},
				Containers: []corev1.Container{
					corev1.Container{Name: "test-a"},
					corev1.Container{Name: "test-b"},
				},
			},
		},
		{
			name: "match regular and init containers",
			existing: corev1.PodSpec{
				InitContainers: []corev1.Container{
					corev1.Container{Name: "test-init"}},
				Containers: []corev1.Container{
					corev1.Container{Name: "test"}}},
			input: corev1.PodSpec{
				InitContainers: []corev1.Container{
					corev1.Container{Name: "test-init"}},
				Containers: []corev1.Container{
					corev1.Container{Name: "test"}}},

			expectedModified: false,
			expected: corev1.PodSpec{
				InitContainers: []corev1.Container{
					corev1.Container{Name: "test-init"}},
				Containers: []corev1.Container{
					corev1.Container{Name: "test"}}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modified := pointer.BoolPtr(false)
			ensurePodSpec(modified, &test.existing, test.input)
			if *modified != test.expectedModified {
				t.Errorf("mismatch modified got: %v want: %v", *modified, test.expectedModified)
			}

			if !equality.Semantic.DeepEqual(test.existing, test.expected) {
				t.Errorf("mismatch PodSpec got:\n%s\nwant:\n%s", yamlOrDie(test.existing), yamlOrDie(test.expected))
			}
		})
	}
}

func yamlOrDie(data interface{}) string {
	bytes, err := yaml.Marshal(data)
	if err != nil {
		panic(err)
	}
	return string(bytes)
}
