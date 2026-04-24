package integration_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	descruntime "ocm.software/open-component-model/bindings/go/descriptor/runtime"
	"ocm.software/open-component-model/bindings/go/runtime"

	"ocm.software/open-component-model/bindings/go/sigstore/signing/handler"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/v1alpha1"
)

//nolint:gosec // these are not secrets
const (
	credOIDCToken           = "token"
	credTrustedRootJSONFile = "trusted_root_json_file"
)

// sigstoreEnv holds the environment configuration for the sigstore integration
// tests. All values are read from environment variables in TestMain, which are
// expected to be set by the scaffolding setup (either via CI or locally via
// hack/extract-sigstore-env.sh).
//
// Trust material can be provided in two ways:
//  1. Via the local TUF cache (~/.sigstore/root/) initialized with the
//     scaffolding's TUF mirror — used by tests that omit TrustedRoot.
//  2. Via an explicit trusted root JSON file (SIGSTORE_TRUSTED_ROOT) — used
//     by tests that pass TrustedRoot in SignConfig/VerifyConfig to exercise
//     the enterprise/private-infra scenario.
type sigstoreEnv struct {
	OIDCToken         string
	SigningConfigPath string
	TrustedRootPath   string
	OIDCIssuer        string
	OIDCIdentity      string
}

// stack is the shared sigstore environment used by all tests.
//
// All tests share the same Rekor transparency log. Each test creates its own
// unique digest (via uniqueDigest), so entries from different tests do not
// interfere. Do not run sub-tests in parallel against the same signed value
// without ensuring digest uniqueness.
var stack *sigstoreEnv

func TestMain(m *testing.M) {
	stack = &sigstoreEnv{
		OIDCToken:         requireEnv("SIGSTORE_OIDC_TOKEN"),
		SigningConfigPath: requireEnv("SIGSTORE_SIGNING_CONFIG"),
		TrustedRootPath:   requireEnv("SIGSTORE_TRUSTED_ROOT"),
		OIDCIssuer:        requireEnv("SIGSTORE_OIDC_ISSUER"),
		OIDCIdentity:      requireEnv("SIGSTORE_OIDC_IDENTITY"),
	}
	os.Exit(m.Run())
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required env var %s is not set", key)
	}
	return v
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func uniqueDigest(t *testing.T, label string) descruntime.Digest {
	t.Helper()
	h := sha256.Sum256([]byte("integration-tc-" + label + "-" + t.Name()))
	return descruntime.Digest{
		HashAlgorithm:          "SHA-256",
		NormalisationAlgorithm: "jsonNormalisation/v2",
		Value:                  hex.EncodeToString(h[:]),
	}
}

type bundleJSON struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		Certificate *struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate"`
		TlogEntries               []json.RawMessage `json:"tlogEntries"`
		TimestampVerificationData json.RawMessage   `json:"timestampVerificationData,omitempty"`
	} `json:"verificationMaterial"`
	MessageSignature *struct {
		Signature string `json:"signature"`
	} `json:"messageSignature"`
}

func decodeBundle(t *testing.T, sigInfo descruntime.SignatureInfo) *bundleJSON {
	t.Helper()
	r := require.New(t)
	raw, err := base64.StdEncoding.DecodeString(sigInfo.Value)
	r.NoError(err)
	var b bundleJSON
	r.NoError(json.Unmarshal(raw, &b))
	return &b
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func Test_Integration_Keyless_IdentityVerification(t *testing.T) {
	r := require.New(t)
	h, err := handler.New()
	r.NoError(err)
	digest := uniqueDigest(t, "identity-verify")

	signCfg := &v1alpha1.SignConfig{
		SigningConfig: stack.SigningConfigPath,
	}
	signCfg.SetType(runtime.NewVersionedType(v1alpha1.SignConfigType, v1alpha1.Version))

	sigInfo, err := h.Sign(t.Context(), digest, signCfg, map[string]string{
		credOIDCToken: stack.OIDCToken,
	})
	r.NoError(err)
	r.NotEmpty(sigInfo.Issuer)

	signed := descruntime.Signature{
		Name:      "integration-tc-identity-test",
		Digest:    digest,
		Signature: sigInfo,
	}

	t.Run("matching issuer succeeds", func(t *testing.T) {
		r := require.New(t)
		verifyCfg := &v1alpha1.VerifyConfig{
			CertificateOIDCIssuer:     sigInfo.Issuer,
			CertificateIdentityRegexp: ".*",
		}
		verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

		err := h.Verify(t.Context(), signed, verifyCfg, nil)
		r.NoError(err)
	})

	t.Run("wrong issuer fails", func(t *testing.T) {
		r := require.New(t)
		verifyCfg := &v1alpha1.VerifyConfig{
			CertificateOIDCIssuer:     "https://wrong-issuer.example.com",
			CertificateIdentityRegexp: ".*",
		}
		verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

		err := h.Verify(t.Context(), signed, verifyCfg, nil)
		r.Error(err)
		r.ErrorContains(err, "issuer")
	})

	t.Run("issuer regex succeeds", func(t *testing.T) {
		r := require.New(t)
		verifyCfg := &v1alpha1.VerifyConfig{
			CertificateOIDCIssuerRegexp: ".*",
			CertificateIdentityRegexp:   ".*",
		}
		verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

		err := h.Verify(t.Context(), signed, verifyCfg, nil)
		r.NoError(err)
	})

	t.Run("matching identity succeeds", func(t *testing.T) {
		r := require.New(t)
		verifyCfg := &v1alpha1.VerifyConfig{
			CertificateOIDCIssuerRegexp: ".*",
			CertificateIdentity:         stack.OIDCIdentity,
		}
		verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

		err := h.Verify(t.Context(), signed, verifyCfg, nil)
		r.NoError(err)
	})

	t.Run("wrong identity fails", func(t *testing.T) {
		r := require.New(t)
		verifyCfg := &v1alpha1.VerifyConfig{
			CertificateOIDCIssuerRegexp: ".*",
			CertificateIdentity:         "wrong@example.com",
		}
		verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

		err := h.Verify(t.Context(), signed, verifyCfg, nil)
		r.Error(err)
	})
}

// Test_Integration_TamperedBundle signs a real digest, then mutates the
// resulting bundle in various ways and asserts that every mutation causes
// verification to fail.  This proves that cosign detects tampered
// signatures / bundles and cannot be fooled by crafted material.
func Test_Integration_TamperedBundle(t *testing.T) {
	r := require.New(t)
	h, err := handler.New()
	r.NoError(err)
	digest := uniqueDigest(t, "tamper")

	signCfg := &v1alpha1.SignConfig{
		SigningConfig: stack.SigningConfigPath,
	}
	signCfg.SetType(runtime.NewVersionedType(v1alpha1.SignConfigType, v1alpha1.Version))

	sigInfo, err := h.Sign(t.Context(), digest, signCfg, map[string]string{
		credOIDCToken: stack.OIDCToken,
	})
	r.NoError(err, "baseline signing must succeed")

	verifyCfg := &v1alpha1.VerifyConfig{
		CertificateOIDCIssuer: stack.OIDCIssuer,
		CertificateIdentity:   stack.OIDCIdentity,
	}
	verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

	// Baseline: the unmodified bundle must verify cleanly.
	signed := descruntime.Signature{
		Name:      "tamper-baseline",
		Digest:    digest,
		Signature: sigInfo,
	}
	r.NoError(h.Verify(t.Context(), signed, verifyCfg, nil), "baseline verification must succeed")

	// mutateBundle decodes the bundle, applies f to the parsed JSON map, and
	// re-encodes it as a base64 string so it can be placed back into a
	// SignatureInfo.Value.
	mutateBundle := func(t *testing.T, r *require.Assertions, f func(m map[string]any)) string {
		t.Helper()
		raw, err := base64.StdEncoding.DecodeString(sigInfo.Value)
		r.NoError(err)
		var m map[string]any
		r.NoError(json.Unmarshal(raw, &m))
		f(m)
		modified, err := json.Marshal(m)
		r.NoError(err)
		return base64.StdEncoding.EncodeToString(modified)
	}

	t.Run("mutated signature bytes rejected", func(t *testing.T) {
		r := require.New(t)
		b := decodeBundle(t, sigInfo)
		r.NotNil(b.MessageSignature, "bundle must have message signature")
		sigBytes, err := base64.StdEncoding.DecodeString(b.MessageSignature.Signature)
		r.NoError(err)
		r.NotEmpty(sigBytes, "baseline signature must be non-empty")
		sigBytes[len(sigBytes)-1] ^= 0xFF

		tampered := mutateBundle(t, r, func(m map[string]any) {
			ms := m["messageSignature"].(map[string]any)
			ms["signature"] = base64.StdEncoding.EncodeToString(sigBytes)
		})

		s := descruntime.Signature{
			Name:   "tamper-sig-bytes",
			Digest: digest,
			Signature: descruntime.SignatureInfo{
				Algorithm: sigInfo.Algorithm,
				MediaType: sigInfo.MediaType,
				Value:     tampered,
				Issuer:    sigInfo.Issuer,
			},
		}
		err = h.Verify(t.Context(), s, verifyCfg, nil)
		r.Error(err, "verification must fail when signature bytes are mutated")
	})

	t.Run("stripped certificate rejected", func(t *testing.T) {
		r := require.New(t)
		tampered := mutateBundle(t, r, func(m map[string]any) {
			vm := m["verificationMaterial"].(map[string]any)
			delete(vm, "certificate")
		})

		s := descruntime.Signature{
			Name:   "tamper-strip-cert",
			Digest: digest,
			Signature: descruntime.SignatureInfo{
				Algorithm: sigInfo.Algorithm,
				MediaType: sigInfo.MediaType,
				Value:     tampered,
				Issuer:    sigInfo.Issuer,
			},
		}
		err := h.Verify(t.Context(), s, verifyCfg, nil)
		r.Error(err, "verification must fail when certificate is stripped from bundle")
	})

	t.Run("stripped tlog entries rejected", func(t *testing.T) {
		r := require.New(t)
		tampered := mutateBundle(t, r, func(m map[string]any) {
			vm := m["verificationMaterial"].(map[string]any)
			vm["tlogEntries"] = []any{}
		})

		s := descruntime.Signature{
			Name:   "tamper-strip-tlog",
			Digest: digest,
			Signature: descruntime.SignatureInfo{
				Algorithm: sigInfo.Algorithm,
				MediaType: sigInfo.MediaType,
				Value:     tampered,
				Issuer:    sigInfo.Issuer,
			},
		}
		err := h.Verify(t.Context(), s, verifyCfg, nil)
		r.Error(err, "verification must fail when tlog entries are stripped from bundle")
	})

	t.Run("wrong digest rejected", func(t *testing.T) {
		r := require.New(t)
		wrongDigest := uniqueDigest(t, "tamper-wrong-digest-other")
		s := descruntime.Signature{
			Name:      "tamper-wrong-digest",
			Digest:    wrongDigest,
			Signature: sigInfo,
		}
		err := h.Verify(t.Context(), s, verifyCfg, nil)
		r.Error(err, "verification must fail when digest does not match signed content")
		r.ErrorContains(err, "verif")
	})

	t.Run("corrupted bundle rejected", func(t *testing.T) {
		r := require.New(t)
		garbage := base64.StdEncoding.EncodeToString([]byte(`{"not":"a valid bundle"}`))
		s := descruntime.Signature{
			Name:   "tamper-corrupt-bundle",
			Digest: digest,
			Signature: descruntime.SignatureInfo{
				Algorithm: sigInfo.Algorithm,
				MediaType: sigInfo.MediaType,
				Value:     garbage,
				Issuer:    sigInfo.Issuer,
			},
		}
		err := h.Verify(t.Context(), s, verifyCfg, nil)
		r.Error(err, "verification must fail for a corrupted/garbage bundle")
	})
}

// Test_Integration_SignAndVerify signs with the full sigstore stack
// (Fulcio + Rekor + TSA), then verifies using the bundle and TUF-cached
// trust material. This exercises the end-to-end sign+verify path and
// validates that the bundle contains all required verification material.
func Test_Integration_SignAndVerify(t *testing.T) {
	r := require.New(t)
	h, err := handler.New()
	r.NoError(err)
	digest := uniqueDigest(t, "sign-and-verify")

	signCfg := &v1alpha1.SignConfig{
		SigningConfig: stack.SigningConfigPath,
	}
	signCfg.SetType(runtime.NewVersionedType(v1alpha1.SignConfigType, v1alpha1.Version))

	sigInfo, err := h.Sign(t.Context(), digest, signCfg, map[string]string{
		credOIDCToken: stack.OIDCToken,
	})
	r.NoError(err, "signing should succeed")

	bundle := decodeBundle(t, sigInfo)

	r.NotNil(bundle.VerificationMaterial.Certificate,
		"bundle must contain a Fulcio certificate for identity verification")
	r.NotEmpty(bundle.VerificationMaterial.Certificate.RawBytes)

	r.NotEmpty(bundle.VerificationMaterial.TlogEntries,
		"bundle must contain tlog entries for transparency verification")
	for i, raw := range bundle.VerificationMaterial.TlogEntries {
		var entry map[string]any
		r.NoError(json.Unmarshal(raw, &entry), "tlog entry %d must be valid JSON", i)
		r.Contains(entry, "inclusionProof", "tlog entry %d must have an inclusion proof", i)
	}

	r.NotNil(bundle.MessageSignature, "bundle must contain the message signature")
	r.NotEmpty(bundle.MessageSignature.Signature)

	r.Equal(v1alpha1.AlgorithmSigstore, sigInfo.Algorithm)
	r.Equal(v1alpha1.MediaTypeSigstoreBundle, sigInfo.MediaType)
	r.NotEmpty(sigInfo.Issuer)

	signed := descruntime.Signature{
		Name:      "sign-and-verify-test",
		Digest:    digest,
		Signature: sigInfo,
	}

	verifyCfg := &v1alpha1.VerifyConfig{
		CertificateOIDCIssuer: stack.OIDCIssuer,
		CertificateIdentity:   stack.OIDCIdentity,
	}
	verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

	err = h.Verify(t.Context(), signed, verifyCfg, nil)
	r.NoError(err, "verification should succeed")

	t.Run("wrong issuer fails", func(t *testing.T) {
		r := require.New(t)
		badCfg := &v1alpha1.VerifyConfig{
			CertificateOIDCIssuer: "https://wrong-issuer.example.com",
			CertificateIdentity:   stack.OIDCIdentity,
		}
		badCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

		err := h.Verify(t.Context(), signed, badCfg, nil)
		r.Error(err, "verification with wrong issuer must fail")
		r.ErrorContains(err, "issuer")
	})

	t.Run("wrong identity fails", func(t *testing.T) {
		r := require.New(t)
		badCfg := &v1alpha1.VerifyConfig{
			CertificateOIDCIssuer: stack.OIDCIssuer,
			CertificateIdentity:   "wrong@example.com",
		}
		badCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

		err := h.Verify(t.Context(), signed, badCfg, nil)
		r.Error(err, "verification with wrong identity must fail")
	})
}

// Test_Integration_SignWithTrustedRoot exercises the enterprise/private-infra
// signing scenario where the signing config AND a trusted root are both passed
// to cosign. When signing against a privately deployed Sigstore infrastructure,
// cosign uses --trusted-root to validate the Fulcio leaf certificate chain
// locally rather than relying on the public-good TUF root.
//
// This test signs with both --signing-config and --trusted-root, then verifies
// with TUF-cached trust material (to prove the bundle is valid) and also with
// the explicit trusted root (to prove the trusted root is correct for verification).
func Test_Integration_SignWithTrustedRoot(t *testing.T) {
	r := require.New(t)
	h, err := handler.New()
	r.NoError(err)
	digest := uniqueDigest(t, "sign-with-trusted-root")

	signCfg := &v1alpha1.SignConfig{
		SigningConfig: stack.SigningConfigPath,
		TrustedRoot:   stack.TrustedRootPath,
	}
	signCfg.SetType(runtime.NewVersionedType(v1alpha1.SignConfigType, v1alpha1.Version))

	sigInfo, err := h.Sign(t.Context(), digest, signCfg, map[string]string{
		credOIDCToken: stack.OIDCToken,
	})
	r.NoError(err, "signing with --trusted-root should succeed")

	bundle := decodeBundle(t, sigInfo)
	r.NotNil(bundle.VerificationMaterial.Certificate,
		"bundle must contain a Fulcio certificate")
	r.NotEmpty(bundle.VerificationMaterial.TlogEntries,
		"bundle must contain tlog entries")
	r.NotNil(bundle.MessageSignature,
		"bundle must contain the message signature")

	r.Equal(v1alpha1.AlgorithmSigstore, sigInfo.Algorithm)
	r.Equal(v1alpha1.MediaTypeSigstoreBundle, sigInfo.MediaType)
	r.NotEmpty(sigInfo.Issuer)

	signed := descruntime.Signature{
		Name:      "sign-with-trusted-root-test",
		Digest:    digest,
		Signature: sigInfo,
	}

	t.Run("verify with TUF-cached trust succeeds", func(t *testing.T) {
		r := require.New(t)
		verifyCfg := &v1alpha1.VerifyConfig{
			CertificateOIDCIssuer:     stack.OIDCIssuer,
			CertificateIdentityRegexp: ".*",
		}
		verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

		err := h.Verify(t.Context(), signed, verifyCfg, nil)
		r.NoError(err, "bundle signed with --trusted-root must also verify via TUF")
	})

	t.Run("verify with explicit trusted root succeeds", func(t *testing.T) {
		r := require.New(t)
		verifyCfg := &v1alpha1.VerifyConfig{
			TrustedRoot:               stack.TrustedRootPath,
			CertificateOIDCIssuer:     stack.OIDCIssuer,
			CertificateIdentityRegexp: ".*",
		}
		verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

		err := h.Verify(t.Context(), signed, verifyCfg, map[string]string{
			credTrustedRootJSONFile: stack.TrustedRootPath,
		})
		r.NoError(err, "bundle signed with --trusted-root must verify with explicit trusted root")
	})
}

// Test_Integration_VerifyWithExplicitTrustedRoot exercises offline/air-gapped
// verification where the trusted root is passed explicitly via VerifyConfig
// and/or credentials, rather than relying on TUF-cached trust.
//
// This is the enterprise scenario where a verifier has no network access to
// TUF mirrors and must verify bundles using only a pre-distributed trusted root.
func Test_Integration_VerifyWithExplicitTrustedRoot(t *testing.T) {
	r := require.New(t)
	h, err := handler.New()
	r.NoError(err)
	digest := uniqueDigest(t, "verify-explicit-trusted-root")

	// Sign using the standard path (signing config, TUF-cached trust).
	signCfg := &v1alpha1.SignConfig{
		SigningConfig: stack.SigningConfigPath,
	}
	signCfg.SetType(runtime.NewVersionedType(v1alpha1.SignConfigType, v1alpha1.Version))

	sigInfo, err := h.Sign(t.Context(), digest, signCfg, map[string]string{
		credOIDCToken: stack.OIDCToken,
	})
	r.NoError(err, "signing should succeed")

	signed := descruntime.Signature{
		Name:      "verify-explicit-trusted-root-test",
		Digest:    digest,
		Signature: sigInfo,
	}

	t.Run("trusted root via config field", func(t *testing.T) {
		r := require.New(t)
		verifyCfg := &v1alpha1.VerifyConfig{
			TrustedRoot:               stack.TrustedRootPath,
			CertificateOIDCIssuer:     stack.OIDCIssuer,
			CertificateIdentityRegexp: ".*",
		}
		verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

		err := h.Verify(t.Context(), signed, verifyCfg, nil)
		r.NoError(err, "verification with trusted root via config field should succeed")
	})

	t.Run("trusted root via credential file path", func(t *testing.T) {
		r := require.New(t)
		verifyCfg := &v1alpha1.VerifyConfig{
			CertificateOIDCIssuer:     stack.OIDCIssuer,
			CertificateIdentityRegexp: ".*",
		}
		verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

		err := h.Verify(t.Context(), signed, verifyCfg, map[string]string{
			credTrustedRootJSONFile: stack.TrustedRootPath,
		})
		r.NoError(err, "verification with trusted root via credential file should succeed")
	})

	t.Run("trusted root via inline credential JSON", func(t *testing.T) {
		r := require.New(t)

		trustedRootJSON, err := os.ReadFile(stack.TrustedRootPath)
		r.NoError(err, "reading trusted root file should succeed")

		verifyCfg := &v1alpha1.VerifyConfig{
			CertificateOIDCIssuer:     stack.OIDCIssuer,
			CertificateIdentityRegexp: ".*",
		}
		verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

		err = h.Verify(t.Context(), signed, verifyCfg, map[string]string{
			"trusted_root_json": string(trustedRootJSON),
		})
		r.NoError(err, "verification with trusted root via inline JSON credential should succeed")
	})

	t.Run("wrong issuer fails with explicit trusted root", func(t *testing.T) {
		r := require.New(t)
		badCfg := &v1alpha1.VerifyConfig{
			TrustedRoot:               stack.TrustedRootPath,
			CertificateOIDCIssuer:     "https://wrong-issuer.example.com",
			CertificateIdentityRegexp: ".*",
		}
		badCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

		err := h.Verify(t.Context(), signed, badCfg, map[string]string{
			credTrustedRootJSONFile: stack.TrustedRootPath,
		})
		r.Error(err, "verification with wrong issuer must fail even with valid trusted root")
		r.ErrorContains(err, "issuer")
	})
}

// Test_Integration_PrivateInfrastructure verifies that the
// PrivateInfrastructure flag propagates correctly through cosign's
// --private-infrastructure flag. The scaffolding cluster IS private
// infrastructure, so signing normally and verifying with
// PrivateInfrastructure: true (plus an explicit trusted root) should succeed.
func Test_Integration_PrivateInfrastructure(t *testing.T) {
	r := require.New(t)
	h, err := handler.New()
	r.NoError(err)
	digest := uniqueDigest(t, "private-infrastructure")

	// Sign using the standard path (signing config, TUF-cached trust).
	signCfg := &v1alpha1.SignConfig{
		SigningConfig: stack.SigningConfigPath,
	}
	signCfg.SetType(runtime.NewVersionedType(v1alpha1.SignConfigType, v1alpha1.Version))

	sigInfo, err := h.Sign(t.Context(), digest, signCfg, map[string]string{
		credOIDCToken: stack.OIDCToken,
	})
	r.NoError(err, "signing should succeed")

	signed := descruntime.Signature{
		Name:      "private-infrastructure-test",
		Digest:    digest,
		Signature: sigInfo,
	}

	// Verify with PrivateInfrastructure: true and an explicit trusted root.
	// This exercises the --private-infrastructure flag path in cosign, which
	// skips online transparency log verification.
	verifyCfg := &v1alpha1.VerifyConfig{
		TrustedRoot:               stack.TrustedRootPath,
		PrivateInfrastructure:     true,
		CertificateOIDCIssuer:     stack.OIDCIssuer,
		CertificateIdentityRegexp: ".*",
	}
	verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

	err = h.Verify(t.Context(), signed, verifyCfg, map[string]string{
		credTrustedRootJSONFile: stack.TrustedRootPath,
	})
	r.NoError(err, "verification with --private-infrastructure and explicit trusted root should succeed")
}

// ---------------------------------------------------------------------------
// Future test scenarios (documented for reference)
// ---------------------------------------------------------------------------
//
// Test_Integration_PublicGoodSigstore (NOT IMPLEMENTED)
//
// This test would exercise the "just works" path where cosign signs and
// verifies using the public-good Sigstore infrastructure (public Fulcio,
// public Rekor, embedded TUF root) with no custom signing config or trusted
// root. This path cannot be tested against the scaffolding cluster because
// scaffolding is private infrastructure.
//
// To test this scenario, run against the real public-good Sigstore:
//   - No --signing-config, no --trusted-root for signing
//   - No --trusted-root for verification
//   - Requires a real OIDC token (e.g., from GitHub Actions OIDC provider)
//
// Test_Integration_GitHubOIDCFlow (NOT IMPLEMENTED)
//
// This test would exercise signing with a GitHub Actions OIDC token obtained
// from ACTIONS_ID_TOKEN_REQUEST_TOKEN / ACTIONS_ID_TOKEN_REQUEST_URL. The
// handler receives the token via the "token" credential key. This requires
// running in a GitHub Actions environment with id-token: write permission.
// The scaffolding's Kubernetes OIDC tokens work for now; the GitHub OIDC
// flow is a future enhancement for testing the full CI/CD signing path.
