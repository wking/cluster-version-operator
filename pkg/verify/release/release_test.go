package release

import (
	"io/ioutil"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/openshift/cluster-version-operator/pkg/verify/store/sigstore"
)

func TestNewFromMap(t *testing.T) {
	redhatData, err := ioutil.ReadFile(filepath.Join("..", "testdata", "keyrings", "redhat.txt"))
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range []struct {
		name           string
		data           map[string]string
		expectedString *regexp.Regexp
		expectedError  *regexp.Regexp
	}{
		{
			name:          "requires data",
			expectedError: regexp.MustCompile("^from_test did not provide any signature stores to read from and cannot be used$"),
		},
		{
			name: "requires stores",
			data: map[string]string{
				"verifier-public-key-redhat": string(redhatData),
			},
			expectedError: regexp.MustCompile("^from_test did not provide any signature stores to read from and cannot be used$"),
		},
		{
			name: "invalid store scheme",
			data: map[string]string{
				"store-local": "file:///signatures",
			},
			expectedError: regexp.MustCompile("^from_test has an invalid key \"store-local\": must be a valid URL with scheme http:// or https://$"),
		},
		{
			name: "requires verifiers",
			data: map[string]string{
				"store-local": "https://example.com/signatures",
			},
			expectedError: regexp.MustCompile("^from_test did not provide any GPG public keys to verify signatures from and cannot be used$"),
		},
		{
			name: "loads valid configuration",
			data: map[string]string{
				"verifier-public-key-redhat": string(redhatData),
				"store-local":                "https://example.com/signatures",
			},
			expectedString: regexp.MustCompile(`^All release image digests must have GPG signatures from verifier-public-key-redhat \(567E347AD0044ADE55BA8A5F199E2F91FD431D51: Red Hat, Inc. \(release key 2\) <security@redhat.com>\) - will check for signatures in containers/image signature store under https://example.com/signatures$`),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := NewFromMap("from_test", testCase.data, sigstore.DefaultClient)
			if err == nil {
				if testCase.expectedError != nil {
					t.Fatalf("NewFromMap succeeded when we expected %s", testCase.expectedError)
				}
			} else if testCase.expectedError == nil {
				t.Fatalf("NewFromMap failed when we expected success: %v", err)
			} else if !testCase.expectedError.MatchString(err.Error()) {
				t.Fatalf("NewFromMap failed with %v (expected %s)", err, testCase.expectedError)
			}

			if got == nil {
				if testCase.expectedString != nil {
					t.Fatal("NewFromMap did not return the expected verifier")
				}
			} else if testCase.expectedString == nil {
				t.Fatalf("NewFromMap returned a verifier when we did not expect one: %s", got)
			} else if !testCase.expectedString.MatchString(got.String()) {
				t.Fatalf("NewFromMap returned %s (expected %s)", got, testCase.expectedString)
			}
		})
	}
}
