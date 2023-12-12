// Package customsignaturestore implements a signature store as configured by ClusterVersion.
package customsignaturestore

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	corev1listers "k8s.io/client-go/listers/core/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/verify/store"
	"github.com/openshift/library-go/pkg/verify/store/parallel"
	"github.com/openshift/library-go/pkg/verify/store/sigstore"
)

type Store struct {
	// Name is the name of the ClusterVersion object that configures this store.
	Name string

	// ClusterVersionLister allows the store to fetch the current ClusterVersion configuration.
	ClusterVersionLister configv1listers.ClusterVersionLister

	// ConfigMapLister allows the store to fetch certificate
	// authority ConfigMaps for per-store trust.
	ConfigMapLister corev1listers.ConfigMapNamespaceLister

	// HTTPClient is called once for each Signatures call to ensure
	// requests are made with the currently-recommended parameters.
	HTTPClient sigstore.HTTPClient

	// lock allows the store to be locked while mutating or accessing internal state.
	lock sync.Mutex

	// customStores tracks the most-recently retrieved ClusterVersion configuration.
	customStores []configv1.SignatureStore
}

// Signatures fetches signatures for the provided digest.
func (s *Store) Signatures(ctx context.Context, name string, digest string, fn store.Callback) error {
	customStores, err := s.refreshConfiguration(ctx)
	if err != nil {
		return err
	}

	if customStores == nil {
		return nil
	}

	if len(customStores) == 0 {
		return errors.New("ClusterVersion spec.signatureStores is an empty array.  Unset signatureStores entirely if you want to to enable the default signature stores.")
	}

	allDone := false

	wrapper := func(ctx context.Context, signature []byte, errIn error) (done bool, err error) {
		done, err = fn(ctx, signature, errIn)
		if done {
			allDone = true
		}
		return done, err
	}

	stores := make([]store.Store, 0, len(customStores))
	for _, customStore := range customStores {
		uri := //FIXME: parse from string to *URL here?  Or earlier in refreshConfiguration
		httpClient := s.HTTPClient
		if customStore.CA.Name != "" {
			//FIXME: wrap httpClient in something that clobbers RootCAs
		}
		stores = append(stores, &sigstore.Store{
			URI:        &uri,
			HTTPClient: httpClient,
		})
	}
	store := &parallel.Store{Stores: stores}
	if err := store.Signatures(ctx, name, digest, wrapper); err != nil || allDone {
		return err
	}
	return errors.New("ClusterVersion spec.signatureStores exhausted without finding a valid signature.")
}

func (s *Store) refreshConfiguration(ctx context.Context) ([]*url.URL, error) {
func (s *Store) refreshConfiguration(ctx context.Context) ([]configv1.SignatureStore, error) {
	config, err := s.Lister.Get(s.Name)
	if err != nil {
		return nil, err
	}

	var customStores []configv1.SignatureStore
	if config.Spec.SignatureStores != nil {
		customStores = make([]*url.URL, 0, len(config.Spec.SignatureStores))
		for _, store := range config.Spec.SignatureStores {
			uri, err := url.Parse(store.URL)
			if err != nil {
				return customStores, err
			}

			customStores = append(customStores, uri)
		}
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	s.customStores = customStores
	return customStores, nil
}

// String returns a description of where this store finds
// signatures.
func (s *Store) String() string {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.customStores == nil {
		return "ClusterVersion signatureStores unset, falling back to default stores"
	} else if len(s.customStores) == 0 {
		return "0 ClusterVersion signatureStores"
	}
	customStores := make([]string, 0, len(s.customStores))
	for _, customStore := range s.customStores {
		name := customStore.URL.String()
		if customStore.CA.Name != "" {
			name = fmt.Sprintf("%s (with custom certificate authorities from %s)", name, customStore.CA.Name)
		}
		customStores = append(customStores, name)
	}
	return fmt.Sprintf("ClusterVersion signatureStores: %s", strings.Join(customStores, ", "))
}
