package integration_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	descruntime "ocm.software/open-component-model/bindings/go/descriptor/runtime"
	"ocm.software/open-component-model/bindings/go/runtime"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/handler"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/v1alpha1"
)

// Credential key constants mirrored from the internal credentials package.
// These must stay in sync with the CredentialKey* constants in
// signing/handler/internal/credentials/credentials.go.
// The internal package boundary prevents direct import from integration tests.
//
//nolint:gosec // these are not secrets
const (
	credOIDCToken           = "token"
	credTrustedRootJSONFile = "trusted_root_json_file"
)

// ---------------------------------------------------------------------------
// testBackend — all core tests iterate over both Rekor v1 and v2
// ---------------------------------------------------------------------------

type testBackend struct {
	Name            string
	RekorURL        string
	RekorVersion    uint32
	TrustedRootPath string
	// RequiresTSA indicates that keyless flows on this backend require a TSA.
	// Rekor v2 does not produce SETs, so Fulcio cert validity requires an RFC 3161 timestamp.
	RequiresTSA bool
}

func backends(t *testing.T) []testBackend {
	t.Helper()

	v1URL := envOrDefault("SIGSTORE_REKOR_URL", "https://rekor.sigstore.dev")
	v1Root := os.Getenv("SIGSTORE_TRUSTED_ROOT_PATH")

	v2URL := os.Getenv("SIGSTORE_REKOR_V2_URL")
	v2Root := os.Getenv("SIGSTORE_REKOR_V2_TRUSTED_ROOT_PATH")

	bs := []testBackend{
		{
			Name:            "rekor-v1",
			RekorURL:        v1URL,
			RekorVersion:    1,
			TrustedRootPath: v1Root,
		},
	}

	if v2URL != "" {
		bs = append(bs, testBackend{
			Name:            "rekor-v2",
			RekorURL:        v2URL,
			RekorVersion:    2,
			TrustedRootPath: v2Root,
			RequiresTSA:     true,
		})
	}

	return bs
}

// ---------------------------------------------------------------------------
// Env helpers
// ---------------------------------------------------------------------------

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fulcioURL() string { return envOrDefault("SIGSTORE_FULCIO_URL", "https://fulcio.sigstore.dev") }
func tsaURL() string    { return os.Getenv("SIGSTORE_TSA_URL") }
func oidcToken() string { return os.Getenv("SIGSTORE_OIDC_TOKEN") }

// ---------------------------------------------------------------------------
// Config builders
// ---------------------------------------------------------------------------

func newTestHandler(t *testing.T) *handler.Handler {
	t.Helper()
	return handler.New()
}

func setSignType(cfg *v1alpha1.SignConfig) {
	cfg.SetType(runtime.NewVersionedType(v1alpha1.SignConfigType, v1alpha1.Version))
}

func setVerifyType(cfg *v1alpha1.VerifyConfig) {
	cfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))
}

// keylessSignConfig returns a signing config for keyless (Fulcio+OIDC) flows.
func keylessSignConfig(b testBackend) *v1alpha1.SignConfig {
	cfg := &v1alpha1.SignConfig{
		RekorURL:     b.RekorURL,
		RekorVersion: b.RekorVersion,
		FulcioURL:    fulcioURL(),
	}
	if tsa := tsaURL(); tsa != "" {
		cfg.TSAURL = tsa
	}
	setSignType(cfg)
	return cfg
}

// keylessVerifyConfig returns a verification config for keyless flows.
func keylessVerifyConfig(b testBackend) *v1alpha1.VerifyConfig {
	cfg := &v1alpha1.VerifyConfig{
		TrustedRootPath: b.TrustedRootPath,
	}
	setVerifyType(cfg)
	return cfg
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func sampleDigest(t *testing.T) descruntime.Digest {
	t.Helper()
	h := sha256.Sum256([]byte("integration test content for sigstore"))
	return descruntime.Digest{
		HashAlgorithm:          "SHA-256",
		NormalisationAlgorithm: "jsonNormalisation/v2",
		Value:                  hex.EncodeToString(h[:]),
	}
}

func uniqueDigest(t *testing.T, label string) descruntime.Digest {
	t.Helper()
	h := sha256.Sum256([]byte("integration-test-" + label + "-" + t.Name()))
	return descruntime.Digest{
		HashAlgorithm:          "SHA-256",
		NormalisationAlgorithm: "jsonNormalisation/v2",
		Value:                  hex.EncodeToString(h[:]),
	}
}

func decodeBundle(t *testing.T, sigInfo descruntime.SignatureInfo) *protobundle.Bundle {
	t.Helper()
	r := require.New(t)
	bundleJSON, err := base64.StdEncoding.DecodeString(sigInfo.Value)
	r.NoError(err)
	var bundle protobundle.Bundle
	r.NoError(protojson.Unmarshal(bundleJSON, &bundle))
	return &bundle
}

// ---------------------------------------------------------------------------
// Keyless tests
// ---------------------------------------------------------------------------

func Test_Integration_Keyless_SignVerify(t *testing.T) {

	token := oidcToken()
	if token == "" {
		t.Skip("skipping: SIGSTORE_OIDC_TOKEN not set")
	}

	for _, b := range backends(t) {
		t.Run(b.Name, func(t *testing.T) {
			if b.TrustedRootPath == "" {
				t.Skipf("skipping: no trusted root path for %s", b.Name)
			}
			if b.RequiresTSA && tsaURL() == "" {
				t.Skipf("skipping: %s keyless requires TSA (SIGSTORE_TSA_URL)", b.Name)
			}

			r := require.New(t)
			h := newTestHandler(t)
			digest := uniqueDigest(t, "keyless")
			signCfg := keylessSignConfig(b)

			sigInfo, err := h.Sign(t.Context(), digest, signCfg, map[string]string{
				credOIDCToken: token,
			})
			r.NoError(err, "keyless signing should succeed")

			r.Equal(v1alpha1.AlgorithmSigstore, sigInfo.Algorithm)
			r.Equal(v1alpha1.MediaTypeSigstoreBundle, sigInfo.MediaType)
			r.NotEmpty(sigInfo.Value)
			r.NotEmpty(sigInfo.Issuer, "keyless signature should have OIDC issuer")

			bundle := decodeBundle(t, sigInfo)
			vm := bundle.GetVerificationMaterial()
			r.NotNil(vm)

			cert := vm.GetCertificate()
			r.NotNil(cert, "keyless bundle must contain a Fulcio certificate")
			r.NotEmpty(cert.GetRawBytes())

			x509Cert, err := x509.ParseCertificate(cert.GetRawBytes())
			r.NoError(err, "certificate should be valid DER")
			r.NotEmpty(x509Cert.URIs, "certificate should have a SAN URI (Fulcio identity)")
			r.False(x509Cert.NotBefore.IsZero(), "certificate should have validity period")

			r.Nil(vm.GetPublicKey(), "keyless bundle should not have a public key hint")
			r.NotEmpty(vm.GetTlogEntries(), "bundle should contain tlog entries")

			entry := vm.GetTlogEntries()[0]
			r.Greater(entry.GetIntegratedTime(), int64(0))
			r.NotEmpty(entry.GetLogId())

			signed := descruntime.Signature{
				Name:      "integration-keyless-test",
				Digest:    digest,
				Signature: sigInfo,
			}

			verifyCfg := keylessVerifyConfig(b)
			verifyCfg.ExpectedSANRegex = ".*"
			verifyCfg.ExpectedIssuerRegex = ".*"

			err = h.Verify(t.Context(), signed, verifyCfg, map[string]string{
				credTrustedRootJSONFile: b.TrustedRootPath,
			})
			r.NoError(err, "keyless verification should succeed")
		})
	}
}

func Test_Integration_Keyless_IdentityVerification(t *testing.T) {

	token := oidcToken()
	if token == "" {
		t.Skip("skipping: SIGSTORE_OIDC_TOKEN not set")
	}

	for _, b := range backends(t) {
		t.Run(b.Name, func(t *testing.T) {
			if b.TrustedRootPath == "" {
				t.Skipf("skipping: no trusted root path for %s", b.Name)
			}
			if b.RequiresTSA && tsaURL() == "" {
				t.Skipf("skipping: %s keyless requires TSA", b.Name)
			}

			r := require.New(t)
			h := newTestHandler(t)
			digest := uniqueDigest(t, "identity-verify")
			signCfg := keylessSignConfig(b)

			sigInfo, err := h.Sign(t.Context(), digest, signCfg, map[string]string{
				credOIDCToken: token,
			})
			r.NoError(err)
			r.NotEmpty(sigInfo.Issuer)

			signed := descruntime.Signature{
				Name:      "integration-identity-test",
				Digest:    digest,
				Signature: sigInfo,
			}

			t.Run("matching issuer succeeds", func(t *testing.T) {
				r := require.New(t)
				verifyCfg := keylessVerifyConfig(b)
				verifyCfg.ExpectedIssuer = sigInfo.Issuer
				verifyCfg.ExpectedSANRegex = ".*"

				err := h.Verify(t.Context(), signed, verifyCfg, map[string]string{
					credTrustedRootJSONFile: b.TrustedRootPath,
				})
				r.NoError(err)
			})

			t.Run("wrong issuer fails", func(t *testing.T) {
				r := require.New(t)
				verifyCfg := keylessVerifyConfig(b)
				verifyCfg.ExpectedIssuer = "https://wrong-issuer.example.com"

				err := h.Verify(t.Context(), signed, verifyCfg, map[string]string{
					credTrustedRootJSONFile: b.TrustedRootPath,
				})
				r.Error(err)
			})

			t.Run("issuer regex succeeds", func(t *testing.T) {
				r := require.New(t)
				verifyCfg := keylessVerifyConfig(b)
				verifyCfg.ExpectedIssuerRegex = ".*"
				verifyCfg.ExpectedSANRegex = ".*"

				err := h.Verify(t.Context(), signed, verifyCfg, map[string]string{
					credTrustedRootJSONFile: b.TrustedRootPath,
				})
				r.NoError(err)
			})
		})
	}
}
