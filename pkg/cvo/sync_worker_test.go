package cvo

import (
	"context"
	"fmt"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/openshift/cluster-version-operator/pkg/payload"
)

func Test_statusWrapper_ReportProgress(t *testing.T) {
	tests := []struct {
		name         string
		previous     SyncWorkerStatus
		next         SyncWorkerStatus
		want         bool
		wantProgress bool
	}{
		{
			name:     "skip updates that clear an error and are at an earlier fraction",
			previous: SyncWorkerStatus{Failure: fmt.Errorf("a"), Actual: configv1.Update{Image: "testing"}, Fraction: 0.1},
			next:     SyncWorkerStatus{Actual: configv1.Update{Image: "testing"}},
			want:     false,
		},
		{
			previous:     SyncWorkerStatus{Failure: fmt.Errorf("a"), Actual: configv1.Update{Image: "testing"}, Fraction: 0.1},
			next:         SyncWorkerStatus{Actual: configv1.Update{Image: "testing2"}},
			want:         true,
			wantProgress: true,
		},
		{
			previous: SyncWorkerStatus{Failure: fmt.Errorf("a"), Actual: configv1.Update{Image: "testing"}},
			next:     SyncWorkerStatus{Actual: configv1.Update{Image: "testing"}},
			want:     true,
		},
		{
			previous: SyncWorkerStatus{Failure: fmt.Errorf("a"), Actual: configv1.Update{Image: "testing"}, Fraction: 0.1},
			next:     SyncWorkerStatus{Failure: fmt.Errorf("a"), Actual: configv1.Update{Image: "testing"}},
			want:     true,
		},
		{
			previous: SyncWorkerStatus{Failure: fmt.Errorf("a"), Actual: configv1.Update{Image: "testing"}, Fraction: 0.1},
			next:     SyncWorkerStatus{Failure: fmt.Errorf("b"), Actual: configv1.Update{Image: "testing"}, Fraction: 0.1},
			want:     true,
		},
		{
			previous:     SyncWorkerStatus{Failure: fmt.Errorf("a"), Actual: configv1.Update{Image: "testing"}, Fraction: 0.1},
			next:         SyncWorkerStatus{Failure: fmt.Errorf("b"), Actual: configv1.Update{Image: "testing"}, Fraction: 0.2},
			want:         true,
			wantProgress: true,
		},
		{
			previous:     SyncWorkerStatus{Actual: configv1.Update{Image: "testing"}, Completed: 1},
			next:         SyncWorkerStatus{Actual: configv1.Update{Image: "testing"}, Completed: 2},
			want:         true,
			wantProgress: true,
		},
		{
			previous:     SyncWorkerStatus{Actual: configv1.Update{Image: "testing-1"}, Completed: 1},
			next:         SyncWorkerStatus{Actual: configv1.Update{Image: "testing-2"}, Completed: 1},
			want:         true,
			wantProgress: true,
		},
		{
			previous: SyncWorkerStatus{Actual: configv1.Update{Image: "testing"}},
			next:     SyncWorkerStatus{Actual: configv1.Update{Image: "testing"}},
			want:     true,
		},
		{
			next:         SyncWorkerStatus{Actual: configv1.Update{Image: "testing"}},
			want:         true,
			wantProgress: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &statusWrapper{
				previousStatus: &tt.previous,
			}
			w.w = &SyncWorker{report: make(chan SyncWorkerStatus, 1)}
			w.Report(tt.next)
			close(w.w.report)
			if tt.want {
				select {
				case evt, ok := <-w.w.report:
					if !ok {
						t.Fatalf("no event")
					}
					if tt.wantProgress != (!evt.LastProgress.IsZero()) {
						t.Errorf("unexpected progress timestamp: %#v", evt)
					}
					evt.LastProgress = time.Time{}
					if evt != tt.next {
						t.Fatalf("unexpected: %#v", evt)
					}
				}
			} else {
				select {
				case evt, ok := <-w.w.report:
					if ok {
						t.Fatalf("unexpected event: %#v", evt)
					}
				}
			}
		})
	}
}

func Test_statusWrapper_ReportGeneration(t *testing.T) {
	tests := []struct {
		name     string
		previous SyncWorkerStatus
		next     SyncWorkerStatus
		want     int64
	}{{
		previous: SyncWorkerStatus{Generation: 1, Step: "Apply", Fraction: 0.1},
		next:     SyncWorkerStatus{Step: "RetreivePayload"},
		want:     1,
	}, {
		previous: SyncWorkerStatus{Generation: 1, Step: "Apply", Fraction: 0.1},
		next:     SyncWorkerStatus{Generation: 2, Step: "Apply", Fraction: 0.5},
		want:     2,
	}, {
		previous: SyncWorkerStatus{Generation: 5, Step: "Apply", Fraction: 0.7},
		next:     SyncWorkerStatus{Generation: 2, Step: "Apply", Fraction: 0.5},
		want:     2,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &statusWrapper{
				previousStatus: &tt.previous,
			}
			w.w = &SyncWorker{report: make(chan SyncWorkerStatus, 1)}
			w.Report(tt.next)
			close(w.w.report)

			select {
			case evt := <-w.w.report:
				if tt.want != evt.Generation {
					t.Fatalf("mismatch: expected generation: %d, got generation: %d", tt.want, evt.Generation)
				}
			}
		})
	}
}
func Test_runThrottledStatusNotifier(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)
	in := make(chan SyncWorkerStatus)
	out := make(chan struct{}, 100)

	go runThrottledStatusNotifier(stopCh, 30*time.Second, 1, in, func() { out <- struct{}{} })

	in <- SyncWorkerStatus{Actual: configv1.Update{Image: "test"}}
	select {
	case <-out:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("should have not throttled")
	}

	in <- SyncWorkerStatus{Reconciling: true, Actual: configv1.Update{Image: "test"}}
	select {
	case <-out:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("should have not throttled")
	}

	in <- SyncWorkerStatus{Failure: fmt.Errorf("a"), Reconciling: true, Actual: configv1.Update{Image: "test"}}
	select {
	case <-out:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("should have not throttled")
	}

	in <- SyncWorkerStatus{Failure: fmt.Errorf("a"), Reconciling: true, Actual: configv1.Update{Image: "test"}}
	select {
	case <-out:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("should have not throttled")
	}

	in <- SyncWorkerStatus{Failure: fmt.Errorf("a"), Reconciling: true, Actual: configv1.Update{Image: "test"}}
	select {
	case <-out:
		t.Fatalf("should have throttled")
	case <-time.After(100 * time.Millisecond):
	}
}

func Test_syncWorker_Start(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	dynamicScheme := runtime.NewScheme()
	//dynamicScheme.AddKnownTypeWithName(schema.GroupVersionKind{Group: "test.cvo.io", Version: "v1", Kind: "TestA"}, &unstructured.Unstructured{})
	dynamicScheme.AddKnownTypeWithName(schema.GroupVersionKind{Group: "test.cvo.io", Version: "v1", Kind: "TestB"}, &unstructured.Unstructured{})
	dynamicClient := dynamicfake.NewSimpleDynamicClient(dynamicScheme)

	worker := NewSyncWorker(
		&fakeDirectoryRetriever{
			Delay: 2*time.Second, // longer than WithTimeout
			Info: PayloadInfo{Directory: "testdata/payloadtest"},
		},
		&testResourceBuilder{client: dynamicClient},
		time.Second/4,
		wait.Backoff{},
		"",
	)

	done := make(chan struct{}, 1)
	go func() {
		worker.Start(ctx, 3)
		done <- struct{}{}
	}()
	worker.Update(1, configv1.Update{Image: "testing", Force: true}, nil, payload.UpdatingPayload)
	<- done
	fmt.Printf("here we are %v\n", worker.status)
	if worker.status.Reconciling {
		t.Fatal("sync worker should not be reconciling after a slow retrieval")
	}
}
