// Package release loads a new verifier from a map, as stored in release images.
package release

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"k8s.io/klog"

	"github.com/openshift/cluster-version-operator/pkg/verify"
	"github.com/openshift/cluster-version-operator/pkg/verify/store"
	"github.com/openshift/cluster-version-operator/pkg/verify/store/serial"
	"github.com/openshift/cluster-version-operator/pkg/verify/store/sigstore"
)

// ReleaseAnnotationConfigMapVerifier is an annotation set on a config map in the
// release payload to indicate that this config map controls signing for the payload.
// Only the first config map within the payload should be used, regardless of whether
// it has data. See NewFromConfigMapData for more.
const ReleaseAnnotationConfigMapVerifier = "release.openshift.io/verification-config-map"

// NewFromMap creates a verifier from map data.  When loading from
// release images, the cluster-version operator will use the first
// config map in the release image payload with the
// ReleaseAnnotationConfigMapVerifier annotation.  Only the first
// payload item in lexographic order will be considered - all others
// are ignored.
//
// The keys within the map define how verification is performed:
//
// verifier-public-key-*: A GPG keyring in ASCII form.  At least one
//   of the keys from each keyring must have signed the release image
//   by digest.
//
// store-*: A URL (scheme http:// or https://) location that contains
//   signatures in the store/sigstore format.
func NewFromMap(src string, data map[string]string, clientBuilder sigstore.HTTPClient) (*verify.Verifier, error) {
	verifiers := make(map[string]openpgp.EntityList)
	var stores []store.Store
	for k, v := range data {
		switch {
		case strings.HasPrefix(k, "verifier-public-key-"):
			keyring, err := loadArmoredOrUnarmoredGPGKeyRing([]byte(v))
			if err != nil {
				return nil, errors.Wrapf(err, "%s has an invalid key %q that must be a GPG public key: %v", src, k, err)
			}
			verifiers[k] = keyring
		case strings.HasPrefix(k, "store-"):
			v = strings.TrimSpace(v)
			u, err := url.Parse(v)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
				return nil, fmt.Errorf("%s has an invalid key %q: must be a valid URL with scheme http:// or https://", src, k)
			}
			stores = append(stores, &sigstore.Store{URI: u, HTTPClient: clientBuilder})
		default:
			klog.Warningf("An unexpected key was found in %s and will be ignored (expected store-* or verifier-public-key-*): %s", src, k)
		}
	}
	if len(stores) == 0 {
		return nil, fmt.Errorf("%s did not provide any signature stores to read from and cannot be used", src)
	}
	if len(verifiers) == 0 {
		return nil, fmt.Errorf("%s did not provide any GPG public keys to verify signatures from and cannot be used", src)
	}

	if len(stores) == 1 {
		return verify.NewVerifier(verifiers, stores[0]), nil
	}
	return verify.NewVerifier(verifiers, &serial.Store{Stores: stores}), nil
}

func loadArmoredOrUnarmoredGPGKeyRing(data []byte) (openpgp.EntityList, error) {
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
	if err == nil {
		return keyring, nil
	}
	return openpgp.ReadKeyRing(bytes.NewReader(data))
}
