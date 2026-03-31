package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
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
	credPrivateKeyPEM       = "private_key_pem"
	credPrivateKeyPEMFile   = "private_key_pem_file"
	credPublicKeyPEM        = "public_key_pem"
	credPublicKeyPEMFile    = "public_key_pem_file"
	credOIDCToken           = "oidc_token"
	credTrustedRootJSONFile = "trusted_root_json_file"
)

const envIntegration = "SIGSTORE_INTEGRATION_TEST"

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

func skipUnlessIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(envIntegration) == "" {
		t.Skipf("skipping: set %s=1 to run Sigstore integration tests", envIntegration)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fulcioURL() string          { return envOrDefault("SIGSTORE_FULCIO_URL", "https://fulcio.sigstore.dev") }
func tsaURL() string             { return os.Getenv("SIGSTORE_TSA_URL") }
func oidcToken() string          { return os.Getenv("SIGSTORE_OIDC_TOKEN") }
func tufMirrorURL() string       { return os.Getenv("SIGSTORE_TUF_MIRROR_URL") }
func tufInitialRootPath() string { return os.Getenv("SIGSTORE_TUF_INITIAL_ROOT_PATH") }

// ---------------------------------------------------------------------------
// Config builders
// ---------------------------------------------------------------------------

func newTestHandler(t *testing.T) *handler.Handler {
	t.Helper()
	return handler.New()
}

func setType(cfg *v1alpha1.Config) {
	cfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))
}

// keyBasedConfig returns a signing/verification config for key-based flows.
func keyBasedConfig(b testBackend) *v1alpha1.Config {
	cfg := &v1alpha1.Config{
		RekorURL:        b.RekorURL,
		RekorVersion:    b.RekorVersion,
		TrustedRootPath: b.TrustedRootPath,
	}
	setType(cfg)
	return cfg
}

// keylessConfig returns a signing config for keyless (Fulcio+OIDC) flows.
func keylessConfig(b testBackend) *v1alpha1.Config {
	cfg := &v1alpha1.Config{
		RekorURL:        b.RekorURL,
		RekorVersion:    b.RekorVersion,
		FulcioURL:       fulcioURL(),
		TrustedRootPath: b.TrustedRootPath,
	}
	if tsa := tsaURL(); tsa != "" {
		cfg.TSAURL = tsa
	}
	setType(cfg)
	return cfg
}

// keylessVerifyConfig returns a verification config for keyless flows.
func keylessVerifyConfig(b testBackend) *v1alpha1.Config {
	cfg := &v1alpha1.Config{
		RekorVersion:    b.RekorVersion,
		TrustedRootPath: b.TrustedRootPath,
	}
	if tsa := tsaURL(); tsa != "" {
		cfg.TSAURL = tsa
	}
	setType(cfg)
	return cfg
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func pemEncodePrivateKey(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func pemEncodePublicKey(t *testing.T, key *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

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

func writeKeyToFile(t *testing.T, pemData string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(p, []byte(pemData), 0o600))
	return p
}

// ---------------------------------------------------------------------------
// Core tests — iterated over all backends
// ---------------------------------------------------------------------------

func Test_Integration_KeyBased_SignVerify(t *testing.T) {
	skipUnlessIntegration(t)

	for _, b := range backends(t) {
		t.Run(b.Name, func(t *testing.T) {
			r := require.New(t)
			h := newTestHandler(t)
			digest := uniqueDigest(t, "keybased")
			cfg := keyBasedConfig(b)

			key := mustECDSAKey(t)
			sigInfo, err := h.Sign(t.Context(), digest, cfg, map[string]string{
				credPrivateKeyPEM: pemEncodePrivateKey(t, key),
			})
			r.NoError(err, "signing should succeed")

			r.Equal(v1alpha1.AlgorithmSigstore, sigInfo.Algorithm)
			r.Equal(v1alpha1.MediaTypeSigstoreBundle, sigInfo.MediaType)
			r.NotEmpty(sigInfo.Value)

			// Bundle structure assertions (replaces the former separate BundleStructure test).
			bundle := decodeBundle(t, sigInfo)
			r.Equal(v1alpha1.MediaTypeSigstoreBundle, bundle.GetMediaType())

			vm := bundle.GetVerificationMaterial()
			r.NotNil(vm)
			r.NotNil(vm.GetPublicKey(), "key-based bundle should have a public key hint")
			r.NotEmpty(vm.GetPublicKey().GetHint())
			r.Nil(vm.GetCertificate(), "key-based bundle should not contain a certificate")
			r.NotEmpty(vm.GetTlogEntries(), "bundle should contain tlog entries")

			entry := vm.GetTlogEntries()[0]
			r.NotEmpty(entry.GetLogId(), "tlog entry should have a log ID")
			r.Greater(entry.GetIntegratedTime(), int64(0))
			r.NotNil(entry.GetKindVersion())
			r.NotEmpty(entry.GetCanonicalizedBody())

			sig := bundle.GetMessageSignature()
			r.NotNil(sig)
			r.NotEmpty(sig.GetSignature())
			r.NotNil(sig.GetMessageDigest())
			r.NotEmpty(sig.GetMessageDigest().GetDigest())

			// Verify round-trip.
			signed := descruntime.Signature{
				Name:      "integration-key-test",
				Digest:    digest,
				Signature: sigInfo,
			}
			err = h.Verify(t.Context(), signed, cfg, map[string]string{
				credPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
			})
			r.NoError(err, "verification should succeed")
		})
	}
}

func Test_Integration_MultipleSigs_SameDigest(t *testing.T) {
	skipUnlessIntegration(t)

	for _, b := range backends(t) {
		t.Run(b.Name, func(t *testing.T) {
			r := require.New(t)
			h := newTestHandler(t)
			digest := uniqueDigest(t, "multi-sig")
			cfg := keyBasedConfig(b)

			keyA := mustECDSAKey(t)
			keyB := mustECDSAKey(t)

			sigInfoA, err := h.Sign(t.Context(), digest, cfg, map[string]string{
				credPrivateKeyPEM: pemEncodePrivateKey(t, keyA),
			})
			r.NoError(err)

			sigInfoB, err := h.Sign(t.Context(), digest, cfg, map[string]string{
				credPrivateKeyPEM: pemEncodePrivateKey(t, keyB),
			})
			r.NoError(err)

			r.NotEqual(sigInfoA.Value, sigInfoB.Value, "different keys produce different bundles")

			signedA := descruntime.Signature{Name: "sig-a", Digest: digest, Signature: sigInfoA}
			signedB := descruntime.Signature{Name: "sig-b", Digest: digest, Signature: sigInfoB}

			r.NoError(h.Verify(t.Context(), signedA, cfg, map[string]string{
				credPublicKeyPEM: pemEncodePublicKey(t, &keyA.PublicKey),
			}))
			r.NoError(h.Verify(t.Context(), signedB, cfg, map[string]string{
				credPublicKeyPEM: pemEncodePublicKey(t, &keyB.PublicKey),
			}))

			err = h.Verify(t.Context(), signedA, cfg, map[string]string{
				credPublicKeyPEM: pemEncodePublicKey(t, &keyB.PublicKey),
			})
			r.Error(err, "cross-key verification must fail")
		})
	}
}

func Test_Integration_TamperedDigest(t *testing.T) {
	skipUnlessIntegration(t)

	for _, b := range backends(t) {
		t.Run(b.Name, func(t *testing.T) {
			r := require.New(t)
			h := newTestHandler(t)
			digest := uniqueDigest(t, "tamper")
			cfg := keyBasedConfig(b)

			key := mustECDSAKey(t)
			sigInfo, err := h.Sign(t.Context(), digest, cfg, map[string]string{
				credPrivateKeyPEM: pemEncodePrivateKey(t, key),
			})
			r.NoError(err)

			tampered := descruntime.Digest{
				HashAlgorithm:          digest.HashAlgorithm,
				NormalisationAlgorithm: digest.NormalisationAlgorithm,
				Value:                  hex.EncodeToString(make([]byte, 32)),
			}

			signed := descruntime.Signature{
				Name:      "integration-tamper-test",
				Digest:    tampered,
				Signature: sigInfo,
			}
			err = h.Verify(t.Context(), signed, cfg, map[string]string{
				credPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
			})
			r.Error(err, "tampered digest must fail verification")
		})
	}
}

func Test_Integration_Keyless_SignVerify(t *testing.T) {
	skipUnlessIntegration(t)

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
			signCfg := keylessConfig(b)

			sigInfo, err := h.Sign(t.Context(), digest, signCfg, map[string]string{
				credOIDCToken: token,
			})
			r.NoError(err, "keyless signing should succeed")

			r.Equal(v1alpha1.AlgorithmSigstore, sigInfo.Algorithm)
			r.Equal(v1alpha1.MediaTypeSigstoreBundle, sigInfo.MediaType)
			r.NotEmpty(sigInfo.Value)
			r.NotEmpty(sigInfo.Issuer, "keyless signature should have OIDC issuer")

			// Bundle structure assertions (replaces the former separate Keyless_BundleStructure test).
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

			// Verify round-trip.
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
	skipUnlessIntegration(t)

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
			signCfg := keylessConfig(b)

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

func Test_Integration_TSA_SignVerify(t *testing.T) {
	skipUnlessIntegration(t)

	tsa := tsaURL()
	if tsa == "" {
		t.Skip("skipping: SIGSTORE_TSA_URL not set")
	}

	for _, b := range backends(t) {
		t.Run(b.Name, func(t *testing.T) {
			r := require.New(t)
			h := newTestHandler(t)
			digest := uniqueDigest(t, "tsa")

			cfg := &v1alpha1.Config{
				RekorURL:        b.RekorURL,
				RekorVersion:    b.RekorVersion,
				TSAURL:          tsa,
				TrustedRootPath: b.TrustedRootPath,
			}
			setType(cfg)

			key := mustECDSAKey(t)
			sigInfo, err := h.Sign(t.Context(), digest, cfg, map[string]string{
				credPrivateKeyPEM: pemEncodePrivateKey(t, key),
			})
			r.NoError(err)

			bundle := decodeBundle(t, sigInfo)
			vm := bundle.GetVerificationMaterial()
			r.NotNil(vm)
			r.NotEmpty(vm.GetTimestampVerificationData().GetRfc3161Timestamps(),
				"bundle should contain RFC 3161 timestamps")

			signed := descruntime.Signature{
				Name:      "integration-tsa-test",
				Digest:    digest,
				Signature: sigInfo,
			}
			err = h.Verify(t.Context(), signed, cfg, map[string]string{
				credPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
			})
			r.NoError(err, "verification with TSA timestamps should succeed")
		})
	}
}

// ---------------------------------------------------------------------------
// Single-backend tests (not iterated)
// ---------------------------------------------------------------------------

func Test_Integration_KeyBased_SignVerify_FileCredentials(t *testing.T) {
	skipUnlessIntegration(t)

	h := newTestHandler(t)

	for _, b := range backends(t) {
		t.Run(b.Name, func(t *testing.T) {
			r := require.New(t)

			digest := uniqueDigest(t, "file-creds-"+b.Name)
			cfg := keyBasedConfig(b)

			key := mustECDSAKey(t)
			privKeyFile := writeKeyToFile(t, pemEncodePrivateKey(t, key))
			pubKeyFile := writeKeyToFile(t, pemEncodePublicKey(t, &key.PublicKey))

			sigInfo, err := h.Sign(t.Context(), digest, cfg, map[string]string{
				credPrivateKeyPEMFile: privKeyFile,
			})
			r.NoError(err)
			r.NotEmpty(sigInfo.Value)

			signed := descruntime.Signature{
				Name:      "integration-file-creds-" + b.Name,
				Digest:    digest,
				Signature: sigInfo,
			}
			err = h.Verify(t.Context(), signed, cfg, map[string]string{
				credPublicKeyPEMFile: pubKeyFile,
			})
			r.NoError(err)
		})
	}
}

// signingConfigV1Path returns a v1-only signing config.
// Uses SIGSTORE_SIGNING_CONFIG_V1_PATH if set, otherwise generates one.
func signingConfigV1Path(t *testing.T) string {
	t.Helper()

	if p := os.Getenv("SIGSTORE_SIGNING_CONFIG_V1_PATH"); p != "" {
		return p
	}

	rURL := envOrDefault("SIGSTORE_REKOR_URL", "https://rekor.sigstore.dev")
	fURL := fulcioURL()

	const tmpl = `{
  "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
  "caUrls": [
    {
      "url": %q,
      "majorApiVersion": 1,
      "validFor": {"start": "2020-01-01T00:00:00Z"}
    }
  ],
  "rekorTlogUrls": [
    {
      "url": %q,
      "majorApiVersion": 1,
      "validFor": {"start": "2020-01-01T00:00:00Z"}
    }
  ],
  "rekorTlogConfig": {"selector": "ANY"}
}`

	content := fmt.Sprintf(tmpl, fURL, rURL)
	p := filepath.Join(t.TempDir(), "signing_config_v1.json")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))

	return p
}

func Test_Integration_SigningConfig(t *testing.T) {
	skipUnlessIntegration(t)

	t.Run("rekor-v1", func(t *testing.T) {
		r := require.New(t)
		h := newTestHandler(t)
		digest := uniqueDigest(t, "signing-config-v1")
		scPath := signingConfigV1Path(t)

		cfg := &v1alpha1.Config{
			SigningConfigPath: scPath,
		}
		setType(cfg)

		key := mustECDSAKey(t)
		sigInfo, err := h.Sign(t.Context(), digest, cfg, map[string]string{
			credPrivateKeyPEM: pemEncodePrivateKey(t, key),
		})
		r.NoError(err, "signing via v1 signing_config should succeed")

		bundle := decodeBundle(t, sigInfo)
		r.NotEmpty(bundle.GetVerificationMaterial().GetTlogEntries(),
			"signing config should route to a Rekor instance")

		signed := descruntime.Signature{
			Name:      "integration-signing-config-v1",
			Digest:    digest,
			Signature: sigInfo,
		}

		verifyCfg := &v1alpha1.Config{
			TrustedRootPath: os.Getenv("SIGSTORE_TRUSTED_ROOT_PATH"),
		}
		setType(verifyCfg)

		err = h.Verify(t.Context(), signed, verifyCfg, map[string]string{
			credPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
		})
		r.NoError(err)
	})

	t.Run("rekor-v2", func(t *testing.T) {
		scPath := os.Getenv("SIGSTORE_SIGNING_CONFIG_V2_PATH")
		if scPath == "" {
			t.Skip("skipping: SIGSTORE_SIGNING_CONFIG_V2_PATH not set")
		}
		v2Root := os.Getenv("SIGSTORE_REKOR_V2_TRUSTED_ROOT_PATH")
		if v2Root == "" {
			t.Skip("skipping: SIGSTORE_REKOR_V2_TRUSTED_ROOT_PATH not set")
		}

		r := require.New(t)
		h := newTestHandler(t)
		digest := uniqueDigest(t, "signing-config-v2")

		cfg := &v1alpha1.Config{
			SigningConfigPath: scPath,
		}
		setType(cfg)

		key := mustECDSAKey(t)
		sigInfo, err := h.Sign(t.Context(), digest, cfg, map[string]string{
			credPrivateKeyPEM: pemEncodePrivateKey(t, key),
		})
		r.NoError(err, "signing via v2 signing_config should succeed")

		bundle := decodeBundle(t, sigInfo)
		r.NotEmpty(bundle.GetVerificationMaterial().GetTlogEntries(),
			"signing config should route to Rekor v2")

		signed := descruntime.Signature{
			Name:      "integration-signing-config-v2",
			Digest:    digest,
			Signature: sigInfo,
		}

		verifyCfg := &v1alpha1.Config{
			TrustedRootPath: v2Root,
			RekorVersion:    2,
		}
		setType(verifyCfg)

		err = h.Verify(t.Context(), signed, verifyCfg, map[string]string{
			credPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
		})
		r.NoError(err)
	})
}

func Test_Integration_TUF_TrustedRoot(t *testing.T) {
	skipUnlessIntegration(t)

	tufURL := tufMirrorURL()
	if tufURL == "" {
		t.Skip("skipping: SIGSTORE_TUF_MIRROR_URL not set")
	}
	initialRootPath := tufInitialRootPath()
	if initialRootPath == "" {
		t.Skip("skipping: SIGSTORE_TUF_INITIAL_ROOT_PATH not set")
	}

	r := require.New(t)
	h := newTestHandler(t)
	digest := uniqueDigest(t, "tuf-root")

	initialRoot, err := os.ReadFile(initialRootPath)
	r.NoError(err, "reading TUF initial root.json")

	// Sign via v1 (key-based), verify via TUF mirror.
	v1URL := envOrDefault("SIGSTORE_REKOR_URL", "https://rekor.sigstore.dev")
	v1Root := os.Getenv("SIGSTORE_TRUSTED_ROOT_PATH")
	signCfg := &v1alpha1.Config{
		RekorURL:        v1URL,
		TrustedRootPath: v1Root,
	}
	setType(signCfg)

	key := mustECDSAKey(t)
	sigInfo, err := h.Sign(t.Context(), digest, signCfg, map[string]string{
		credPrivateKeyPEM: pemEncodePrivateKey(t, key),
	})
	r.NoError(err)

	signed := descruntime.Signature{
		Name:      "integration-tuf-root",
		Digest:    digest,
		Signature: sigInfo,
	}

	verifyCfg := &v1alpha1.Config{
		TUFRootURL:     tufURL,
		TUFInitialRoot: string(initialRoot),
	}
	setType(verifyCfg)

	err = h.Verify(t.Context(), signed, verifyCfg, map[string]string{
		credPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
	})
	r.NoError(err, "verification via TUF trusted root should succeed")
}

func Test_Integration_SkipRekor_KeyBased(t *testing.T) {
	skipUnlessIntegration(t)
	r := require.New(t)

	h := newTestHandler(t)
	digest := uniqueDigest(t, "skip-rekor")

	// Sign normally with Rekor v1 — the bundle will contain a tlog entry.
	v1URL := envOrDefault("SIGSTORE_REKOR_URL", "https://rekor.sigstore.dev")
	v1Root := os.Getenv("SIGSTORE_TRUSTED_ROOT_PATH")
	signCfg := &v1alpha1.Config{
		RekorURL:        v1URL,
		TrustedRootPath: v1Root,
	}
	setType(signCfg)

	key := mustECDSAKey(t)
	sigInfo, err := h.Sign(t.Context(), digest, signCfg, map[string]string{
		credPrivateKeyPEM: pemEncodePrivateKey(t, key),
	})
	r.NoError(err)

	signed := descruntime.Signature{
		Name:      "integration-skip-rekor",
		Digest:    digest,
		Signature: sigInfo,
	}

	// Verify with SkipRekor: only checks the signature against the public key,
	// tlog entries in the bundle are ignored.
	verifyCfg := &v1alpha1.Config{
		SkipRekor:       true,
		TrustedRootPath: v1Root,
	}
	setType(verifyCfg)

	err = h.Verify(t.Context(), signed, verifyCfg, map[string]string{
		credPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
	})
	r.NoError(err, "SkipRekor key-based verification should succeed")
}
