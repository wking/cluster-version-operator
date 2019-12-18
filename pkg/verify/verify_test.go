package verify

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"

	"golang.org/x/crypto/openpgp"

	"github.com/openshift/cluster-version-operator/pkg/verify/store"
	"github.com/openshift/cluster-version-operator/pkg/verify/store/memory"
)

func Test_Verifier_Verify(t *testing.T) {
	ctx := context.Background()

	data, err := ioutil.ReadFile(filepath.Join("testdata", "keyrings", "redhat.txt"))
	if err != nil {
		t.Fatal(err)
	}
	redhatPublic, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}
	data, err = ioutil.ReadFile(filepath.Join("testdata", "keyrings", "simple.txt"))
	if err != nil {
		t.Fatal(err)
	}
	simple, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}
	data, err = ioutil.ReadFile(filepath.Join("testdata", "keyrings", "combined.txt"))
	if err != nil {
		t.Fatal(err)
	}
	combined, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	sigE3F1, err := ioutil.ReadFile(filepath.Join("testdata", "signatures", "sha256=e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7", "signature-1"))
	if err != nil {
		t.Fatal(err)
	}
	sigEDD9, err := ioutil.ReadFile(filepath.Join("testdata", "signatures", "sha256=edd9824f0404f1a139688017e7001370e2f3fbc088b94da84506653b473fe140", "signature-1"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		verifiers     map[string]openpgp.EntityList
		store         store.Store
		releaseName   string
		releaseDigest string
		expectedError *regexp.Regexp
	}{
		{
			name:          "no verifiers",
			expectedError: regexp.MustCompile("^the release verifier is incorrectly configured with no verifieries, unable to verify digests$"),
		},
		{
			name:          "no store",
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			expectedError: regexp.MustCompile("^the release verifier is incorrectly configured with no signature store, unable to verify digests$"),
		},
		{
			name:          "empty digest",
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			store:         &memory.Store{},
			releaseDigest: "",
			expectedError: regexp.MustCompile("^release images that are not accessed via digest cannot be verified$"),
		},
		{
			name:          "invalid digest character",
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			store:         &memory.Store{},
			releaseDigest: "!",
			expectedError: regexp.MustCompile("^the provided release image digest has an invalid format$"),
		},
		{
			name:          "no signatures",
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			store:         &memory.Store{},
			releaseDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			expectedError: regexp.MustCompile("^unable to locate a valid signature for one or more sources$"),
		},
		{
			name:          "valid name and signature",
			releaseName:   "registry.access.redhat.com/rhel7:7.6",
			releaseDigest: "sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7",
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			store: &memory.Store{
				Data: map[string][][]byte{
					"sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7": [][]byte{sigE3F1},
				},
			},
		},
		{
			name:          "invalid name with valid signature",
			releaseName:   "quay.io/openshift-release-dev/ocp-release:4.1.0",
			releaseDigest: "sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7",
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			store: &memory.Store{
				Data: map[string][][]byte{
					"sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7": [][]byte{sigE3F1},
				},
			},
			expectedError: regexp.MustCompile("^unable to locate a valid signature for one or more sources$"),
		},
		{
			name:          "valid name with invalid signature",
			releaseName:   "registry.access.redhat.com/rhel7:7.6",
			releaseDigest: "sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7",
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			store: &memory.Store{
				Data: map[string][][]byte{
					"sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7": [][]byte{sigEDD9},
				},
			},
			expectedError: regexp.MustCompile("^unable to locate a valid signature for one or more sources$"),
		},
		{
			name:          "valid signature for sha over http with custom gpg key",
			releaseName:   "registry.svc.ci.openshift.org/ocp/release:4.0.0-0.ci-2019-04-19-181452",
			releaseDigest: "sha256:edd9824f0404f1a139688017e7001370e2f3fbc088b94da84506653b473fe140",
			verifiers:     map[string]openpgp.EntityList{"simple": simple},
			store: &memory.Store{
				Data: map[string][][]byte{
					"sha256:edd9824f0404f1a139688017e7001370e2f3fbc088b94da84506653b473fe140": [][]byte{sigEDD9},
				},
			},
		},
		{
			name:          "valid signature for sha over http with multi-key keyring",
			releaseName:   "registry.svc.ci.openshift.org/ocp/release:4.0.0-0.ci-2019-04-19-181452",
			releaseDigest: "sha256:edd9824f0404f1a139688017e7001370e2f3fbc088b94da84506653b473fe140",
			store: &memory.Store{
				Data: map[string][][]byte{
					"sha256:edd9824f0404f1a139688017e7001370e2f3fbc088b94da84506653b473fe140": [][]byte{sigEDD9},
				},
			},
			verifiers: map[string]openpgp.EntityList{"combined": combined},
		},
		{
			name:          "no signature found",
			releaseDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			store:         &memory.Store{},
			expectedError: regexp.MustCompile("^unable to locate a valid signature for one or more sources$"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewVerifier(tt.verifiers, tt.store).Verify(ctx, tt.releaseName, tt.releaseDigest)
			if err == nil {
				if tt.expectedError != nil {
					t.Fatalf("verify succeeded when we expected %s", tt.expectedError)
				}
			} else if tt.expectedError == nil {
				t.Fatalf("verify failed when we expected success: %v", err)
			} else if !tt.expectedError.MatchString(err.Error()) {
				t.Fatalf("verify failed with %v (expected %s)", err, tt.expectedError)
			}
		})
	}
}

func Test_Verifier_String(t *testing.T) {
	data, err := ioutil.ReadFile(filepath.Join("testdata", "keyrings", "redhat.txt"))
	if err != nil {
		t.Fatal(err)
	}
	redhatPublic, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		verifiers map[string]openpgp.EntityList
		store     store.Store
		want      string
	}{
		{
			name: "no verifiers and no store",
			want: `All release image digests must have GPG signatures from <ERROR: no verifiers> - <ERROR: no store>`,
		},
		{
			name:  "no verifiers",
			store: &memory.Store{},
			want:  `All release image digests must have GPG signatures from <ERROR: no verifiers> - will check for signatures in in-memory signature store`,
		},
		{
			name: "verifiers and store",
			verifiers: map[string]openpgp.EntityList{
				"redhat": redhatPublic,
			},
			store: &memory.Store{},
			want:  `All release image digests must have GPG signatures from redhat (567E347AD0044ADE55BA8A5F199E2F91FD431D51: Red Hat, Inc. (release key 2) <security@redhat.com>) - will check for signatures in in-memory signature store`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Verifier{
				verifiers: tt.verifiers,
				store:     tt.store,
			}
			if got := v.String(); got != tt.want {
				t.Errorf("Verifier.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Verifier_Signatures(t *testing.T) {
	ctx := context.Background()
	data, err := ioutil.ReadFile(filepath.Join("testdata", "keyrings", "redhat.txt"))
	if err != nil {
		t.Fatal(err)
	}
	redhatPublic, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	sigE3F1, err := ioutil.ReadFile(filepath.Join("testdata", "signatures", "sha256=e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7", "signature-1"))
	if err != nil {
		t.Fatal(err)
	}
	sigEDD9, err := ioutil.ReadFile(filepath.Join("testdata", "signatures", "sha256=edd9824f0404f1a139688017e7001370e2f3fbc088b94da84506653b473fe140", "signature-1"))
	if err != nil {
		t.Fatal(err)
	}

	const releaseName = "registry.access.redhat.com/rhel7:7.6"
	const signedDigest = "sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7"

	// verify we don't cache a negative result
	verifier := NewVerifier(
		map[string]openpgp.EntityList{"redhat": redhatPublic},
		&memory.Store{
			Data: map[string][][]byte{
				signedDigest: [][]byte{sigEDD9},
			},
		},
	)
	if err := verifier.Verify(ctx, releaseName, signedDigest); err == nil || err.Error() != "unable to locate a valid signature for one or more sources" {
		t.Fatal(err)
	}
	if sigs := verifier.Signatures(); len(sigs) != 0 {
		t.Fatalf("%#v", sigs)
	}

	// verify we cache a valid request
	verifier = NewVerifier(
		map[string]openpgp.EntityList{"redhat": redhatPublic},
		&memory.Store{
			Data: map[string][][]byte{
				signedDigest: [][]byte{sigE3F1},
			},
		},
	)
	if err := verifier.Verify(ctx, releaseName, signedDigest); err != nil {
		t.Fatal(err)
	}
	if sigs := verifier.Signatures(); len(sigs) != 1 {
		t.Fatalf("%#v", sigs)
	}

	// verify we hit the cache instead of verifying, even with a useless store
	verifier.store = &memory.Store{}
	if err := verifier.Verify(ctx, releaseName, signedDigest); err != nil {
		t.Fatal(err)
	}
	if sigs := verifier.Signatures(); len(sigs) != 1 {
		t.Fatalf("%#v", sigs)
	}

	// verify we maintain a maximum number of cache entries a valid request
	verifier = NewVerifier(
		map[string]openpgp.EntityList{"redhat": redhatPublic},
		&memory.Store{
			Data: map[string][][]byte{
				signedDigest: [][]byte{sigE3F1},
			},
		},
	)
	for i := 0; i < maxSignatureCacheSize*2; i++ {
		verifier.signatureCache[fmt.Sprintf("test-%d", i)] = [][]byte{[]byte("blah")}
	}

	if err := verifier.Verify(ctx, releaseName, signedDigest); err != nil {
		t.Fatal(err)
	}
	if sigs := verifier.Signatures(); len(sigs) != maxSignatureCacheSize || !reflect.DeepEqual(sigs[signedDigest], [][]byte{sigE3F1}) {
		t.Fatalf("%d %#v", len(sigs), sigs)
	}
}
