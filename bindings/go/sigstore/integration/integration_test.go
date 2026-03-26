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
// These must stay in sync with handler/internal/credentials/credentials.go.
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

func skipUnlessIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(envIntegration) == "" {
		t.Skipf("skipping: set %s=1 to run Sigstore integration tests", envIntegration)
	}
}

func rekorURL() string {
	if u := os.Getenv("SIGSTORE_REKOR_URL"); u != "" {
		return u
	}
	return "https://rekor.sigstore.dev"
}

func fulcioURL() string {
	if u := os.Getenv("SIGSTORE_FULCIO_URL"); u != "" {
		return u
	}
	return "https://fulcio.sigstore.dev"
}

func rekorV2URL() string {
	if u := os.Getenv("SIGSTORE_REKOR_V2_URL"); u != "" {
		return u
	}
	return rekorURL()
}

func rekorV2TrustedRootPath() string {
	return os.Getenv("SIGSTORE_REKOR_V2_TRUSTED_ROOT_PATH")
}

func tsaURL() string {
	return os.Getenv("SIGSTORE_TSA_URL")
}

func oidcToken() string {
	return os.Getenv("SIGSTORE_OIDC_TOKEN")
}

func trustedRootPath() string {
	return os.Getenv("SIGSTORE_TRUSTED_ROOT_PATH")
}

func tufMirrorURL() string {
	return os.Getenv("SIGSTORE_TUF_MIRROR_URL")
}

func newTestHandler(t *testing.T) *handler.Handler {
	t.Helper()
	return handler.New(v1alpha1.Scheme)
}

func configWithRekor(t *testing.T) *v1alpha1.Config {
	t.Helper()
	cfg := &v1alpha1.Config{
		RekorURL:        rekorURL(),
		TrustedRootPath: trustedRootPath(),
	}
	cfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))
	return cfg
}

func configWithAllServices(t *testing.T) *v1alpha1.Config {
	t.Helper()
	cfg := &v1alpha1.Config{
		RekorURL:        rekorURL(),
		FulcioURL:       fulcioURL(),
		TrustedRootPath: trustedRootPath(),
	}
	if tsa := tsaURL(); tsa != "" {
		cfg.TSAURL = tsa
		cfg.ForceTSA = true
	}
	cfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))
	return cfg
}

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

// --------------------------------------------------------------------------
// Key-based signing with real Rekor
// --------------------------------------------------------------------------

// Test_Integration_KeyBased_SignVerify_WithRekor signs with an ECDSA key pair
// and publishes to a real Rekor transparency log, then verifies the signature.
//
// This test creates a persistent entry in the transparency log.
func Test_Integration_KeyBased_SignVerify_WithRekor(t *testing.T) {
	skipUnlessIntegration(t)
	r := require.New(t)

	h := newTestHandler(t)
	digest := sampleDigest(t)
	cfg := configWithRekor(t)

	key := mustECDSAKey(t)
	signCreds := map[string]string{
		credPrivateKeyPEM: pemEncodePrivateKey(t, key),
	}

	sigInfo, err := h.Sign(t.Context(), digest, cfg, signCreds)
	r.NoError(err, "signing with Rekor should succeed")

	r.Equal(v1alpha1.AlgorithmSigstore, sigInfo.Algorithm)
	r.Equal(v1alpha1.MediaTypeSigstoreBundle, sigInfo.MediaType)
	r.NotEmpty(sigInfo.Value)

	bundle := decodeBundle(t, sigInfo)

	vm := bundle.GetVerificationMaterial()
	r.NotNil(vm, "bundle should have verification material")
	r.NotEmpty(vm.GetTlogEntries(), "bundle should contain at least one transparency log entry")

	tlogEntry := vm.GetTlogEntries()[0]
	r.NotEmpty(tlogEntry.GetLogId(), "tlog entry should have a log ID")
	r.Greater(tlogEntry.GetIntegratedTime(), int64(0), "tlog entry should have integrated time")
	r.NotEmpty(tlogEntry.GetInclusionPromise().GetSignedEntryTimestamp(), "tlog entry should have inclusion promise")

	r.NotNil(bundle.GetMessageSignature(), "bundle should have message signature")
	r.NotEmpty(bundle.GetMessageSignature().GetSignature())

	signed := descruntime.Signature{
		Name:      "integration-key-test",
		Digest:    digest,
		Signature: sigInfo,
	}

	verifyCreds := map[string]string{
		credPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
	}

	err = h.Verify(t.Context(), signed, cfg, verifyCreds)
	r.NoError(err, "key-based verification with Rekor should succeed")
}

// --------------------------------------------------------------------------
// Key-based signing with file credentials
// --------------------------------------------------------------------------

func Test_Integration_KeyBased_SignVerify_FileCredentials(t *testing.T) {
	skipUnlessIntegration(t)
	r := require.New(t)

	h := newTestHandler(t)
	digest := uniqueDigest(t, "file-creds")
	cfg := configWithRekor(t)

	key := mustECDSAKey(t)
	privKeyFile := writeKeyToFile(t, pemEncodePrivateKey(t, key))
	pubKeyFile := writeKeyToFile(t, pemEncodePublicKey(t, &key.PublicKey))

	signCreds := map[string]string{
		credPrivateKeyPEMFile: privKeyFile,
	}

	sigInfo, err := h.Sign(t.Context(), digest, cfg, signCreds)
	r.NoError(err, "signing with file-based private key should succeed")
	r.NotEmpty(sigInfo.Value)

	signed := descruntime.Signature{
		Name:      "integration-file-creds",
		Digest:    digest,
		Signature: sigInfo,
	}

	verifyCreds := map[string]string{
		credPublicKeyPEMFile: pubKeyFile,
	}

	err = h.Verify(t.Context(), signed, cfg, verifyCreds)
	r.NoError(err, "verification with file-based public key should succeed")
}

// --------------------------------------------------------------------------
// Multiple signatures on the same digest
// --------------------------------------------------------------------------

func Test_Integration_MultipleSigs_SameDigest(t *testing.T) {
	skipUnlessIntegration(t)
	r := require.New(t)

	h := newTestHandler(t)
	digest := uniqueDigest(t, "multi-sig")
	cfg := configWithRekor(t)

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

	signedA := descruntime.Signature{
		Name:      "sig-a",
		Digest:    digest,
		Signature: sigInfoA,
	}
	signedB := descruntime.Signature{
		Name:      "sig-b",
		Digest:    digest,
		Signature: sigInfoB,
	}

	r.NoError(h.Verify(t.Context(), signedA, cfg, map[string]string{
		credPublicKeyPEM: pemEncodePublicKey(t, &keyA.PublicKey),
	}))

	r.NoError(h.Verify(t.Context(), signedB, cfg, map[string]string{
		credPublicKeyPEM: pemEncodePublicKey(t, &keyB.PublicKey),
	}))

	// Cross-verification must fail
	err = h.Verify(t.Context(), signedA, cfg, map[string]string{
		credPublicKeyPEM: pemEncodePublicKey(t, &keyB.PublicKey),
	})
	r.Error(err, "verifying sig-a with key-b should fail")
}

// --------------------------------------------------------------------------
// Tampered digest detection with real Rekor
// --------------------------------------------------------------------------

func Test_Integration_TamperedDigest_WithRekor(t *testing.T) {
	skipUnlessIntegration(t)
	r := require.New(t)

	h := newTestHandler(t)
	digest := uniqueDigest(t, "tamper")
	cfg := configWithRekor(t)

	key := mustECDSAKey(t)
	signCreds := map[string]string{
		credPrivateKeyPEM: pemEncodePrivateKey(t, key),
	}

	sigInfo, err := h.Sign(t.Context(), digest, cfg, signCreds)
	r.NoError(err)

	tamperedDigest := descruntime.Digest{
		HashAlgorithm:          digest.HashAlgorithm,
		NormalisationAlgorithm: digest.NormalisationAlgorithm,
		Value:                  hex.EncodeToString(make([]byte, 32)),
	}

	signed := descruntime.Signature{
		Name:      "integration-tamper-test",
		Digest:    tamperedDigest,
		Signature: sigInfo,
	}

	err = h.Verify(t.Context(), signed, cfg, map[string]string{
		credPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
	})
	r.Error(err, "verification with tampered digest should fail against real Rekor")
}

// --------------------------------------------------------------------------
// Bundle structure validation (key-based)
// --------------------------------------------------------------------------

func Test_Integration_BundleStructure_KeyBased(t *testing.T) {
	skipUnlessIntegration(t)
	r := require.New(t)

	h := newTestHandler(t)
	digest := uniqueDigest(t, "bundle-struct")
	cfg := configWithRekor(t)

	key := mustECDSAKey(t)
	sigInfo, err := h.Sign(t.Context(), digest, cfg, map[string]string{
		credPrivateKeyPEM: pemEncodePrivateKey(t, key),
	})
	r.NoError(err)

	bundle := decodeBundle(t, sigInfo)

	r.Equal(v1alpha1.MediaTypeSigstoreBundle, bundle.GetMediaType())

	vm := bundle.GetVerificationMaterial()
	r.NotNil(vm)

	r.NotNil(vm.GetPublicKey(), "key-based signing should produce public key hint, not certificate")
	r.NotEmpty(vm.GetPublicKey().GetHint())
	r.Nil(vm.GetCertificate(), "key-based signing should not produce a certificate")

	r.NotEmpty(vm.GetTlogEntries())
	entry := vm.GetTlogEntries()[0]
	r.NotNil(entry.GetKindVersion())
	r.NotEmpty(entry.GetCanonicalizedBody())

	sig := bundle.GetMessageSignature()
	r.NotNil(sig)
	r.NotEmpty(sig.GetSignature())
	r.NotNil(sig.GetMessageDigest())
	r.NotEmpty(sig.GetMessageDigest().GetDigest())
}

// --------------------------------------------------------------------------
// Keyless (Fulcio + OIDC + Rekor) signing and verification
// --------------------------------------------------------------------------

// Test_Integration_Keyless_SignVerify_WithFulcioAndRekor performs a full keyless
// signing flow using Fulcio (certificate authority) and Rekor (transparency log).
//
// Requires a pre-obtained OIDC token via SIGSTORE_OIDC_TOKEN env var.
// For CI, use sigstore/scaffolding to obtain tokens automatically.
// For local Kind clusters, use the scaffolding gettoken service.
func Test_Integration_Keyless_SignVerify_WithFulcioAndRekor(t *testing.T) {
	skipUnlessIntegration(t)

	token := oidcToken()
	if token == "" {
		t.Skip("skipping keyless test: SIGSTORE_OIDC_TOKEN not set")
	}

	rootPath := trustedRootPath()
	if rootPath == "" {
		t.Skip("skipping keyless test: SIGSTORE_TRUSTED_ROOT_PATH not set (needed for certificate chain verification)")
	}

	r := require.New(t)
	h := newTestHandler(t)
	digest := sampleDigest(t)
	cfg := configWithAllServices(t)

	signCreds := map[string]string{
		credOIDCToken: token,
	}

	sigInfo, err := h.Sign(t.Context(), digest, cfg, signCreds)
	r.NoError(err, "keyless signing with Fulcio and Rekor should succeed")

	r.Equal(v1alpha1.AlgorithmSigstore, sigInfo.Algorithm)
	r.Equal(v1alpha1.MediaTypeSigstoreBundle, sigInfo.MediaType)
	r.NotEmpty(sigInfo.Value)
	r.NotEmpty(sigInfo.Issuer, "keyless signature should have an OIDC issuer")

	bundle := decodeBundle(t, sigInfo)

	vm := bundle.GetVerificationMaterial()
	r.NotNil(vm)
	r.NotNil(vm.GetCertificate(), "keyless bundle should contain a Fulcio certificate")
	r.NotEmpty(vm.GetCertificate().GetRawBytes(), "certificate should have raw bytes")
	r.NotEmpty(vm.GetTlogEntries(), "bundle should contain a Rekor transparency log entry")

	signed := descruntime.Signature{
		Name:      "integration-keyless-test",
		Digest:    digest,
		Signature: sigInfo,
	}

	verifyCreds := map[string]string{
		credTrustedRootJSONFile: rootPath,
	}

	err = h.Verify(t.Context(), signed, cfg, verifyCreds)
	r.NoError(err, "keyless verification with trusted root should succeed")
}

// --------------------------------------------------------------------------
// Keyless bundle structure deep inspection
// --------------------------------------------------------------------------

func Test_Integration_Keyless_BundleStructure(t *testing.T) {
	skipUnlessIntegration(t)

	token := oidcToken()
	if token == "" {
		t.Skip("skipping: SIGSTORE_OIDC_TOKEN not set")
	}

	r := require.New(t)
	h := newTestHandler(t)
	digest := uniqueDigest(t, "keyless-bundle")
	cfg := configWithAllServices(t)

	sigInfo, err := h.Sign(t.Context(), digest, cfg, map[string]string{
		credOIDCToken: token,
	})
	r.NoError(err)

	bundle := decodeBundle(t, sigInfo)

	vm := bundle.GetVerificationMaterial()
	r.NotNil(vm)

	cert := vm.GetCertificate()
	r.NotNil(cert, "keyless bundle must contain certificate")
	r.NotEmpty(cert.GetRawBytes())

	x509Cert, err := x509.ParseCertificate(cert.GetRawBytes())
	r.NoError(err, "certificate should be valid DER")
	// Fulcio certs have an empty Subject DN; identity is in the SAN URI.
	r.NotEmpty(x509Cert.URIs, "certificate should have a SAN URI (Fulcio identity)")
	r.NotEmpty(x509Cert.Issuer.String(), "certificate should have an issuer")
	r.False(x509Cert.NotBefore.IsZero(), "certificate should have validity period")

	r.Nil(vm.GetPublicKey(), "keyless bundle should not have a public key hint (uses cert)")

	r.NotEmpty(vm.GetTlogEntries())
	entry := vm.GetTlogEntries()[0]
	r.Greater(entry.GetIntegratedTime(), int64(0))
	r.NotEmpty(entry.GetLogId())
}

// --------------------------------------------------------------------------
// Keyless signing with identity verification (Req 4 against real services)
// --------------------------------------------------------------------------

func Test_Integration_Keyless_IdentityVerification(t *testing.T) {
	skipUnlessIntegration(t)

	token := oidcToken()
	if token == "" {
		t.Skip("skipping: SIGSTORE_OIDC_TOKEN not set")
	}
	rootPath := trustedRootPath()
	if rootPath == "" {
		t.Skip("skipping: SIGSTORE_TRUSTED_ROOT_PATH not set")
	}

	r := require.New(t)
	h := newTestHandler(t)
	digest := uniqueDigest(t, "identity-verify")
	cfg := configWithAllServices(t)

	sigInfo, err := h.Sign(t.Context(), digest, cfg, map[string]string{
		credOIDCToken: token,
	})
	r.NoError(err)
	r.NotEmpty(sigInfo.Issuer)

	signed := descruntime.Signature{
		Name:      "integration-identity-test",
		Digest:    digest,
		Signature: sigInfo,
	}

	t.Run("verification with matching issuer succeeds", func(t *testing.T) {
		r := require.New(t)
		verifyCfg := configWithAllServices(t)
		verifyCfg.ExpectedIssuer = sigInfo.Issuer
		verifyCfg.ExpectedSANRegex = ".*"

		err := h.Verify(t.Context(), signed, verifyCfg, map[string]string{
			credTrustedRootJSONFile: rootPath,
		})
		r.NoError(err, "verification with correct issuer should succeed")
	})

	t.Run("verification with wrong issuer fails", func(t *testing.T) {
		r := require.New(t)
		verifyCfg := configWithAllServices(t)
		verifyCfg.ExpectedIssuer = "https://wrong-issuer.example.com"

		err := h.Verify(t.Context(), signed, verifyCfg, map[string]string{
			credTrustedRootJSONFile: rootPath,
		})
		r.Error(err, "verification with wrong issuer should fail")
	})

	t.Run("verification with issuer regex succeeds", func(t *testing.T) {
		r := require.New(t)
		verifyCfg := configWithAllServices(t)
		verifyCfg.ExpectedIssuerRegex = ".*"
		verifyCfg.ExpectedSANRegex = ".*"

		err := h.Verify(t.Context(), signed, verifyCfg, map[string]string{
			credTrustedRootJSONFile: rootPath,
		})
		r.NoError(err, "verification with wildcard issuer regex should succeed")
	})
}

// --------------------------------------------------------------------------
// TSA (Timestamp Authority) integration
// --------------------------------------------------------------------------

func Test_Integration_TSA_SignVerify(t *testing.T) {
	skipUnlessIntegration(t)

	tsa := tsaURL()
	if tsa == "" {
		t.Skip("skipping TSA test: SIGSTORE_TSA_URL not set")
	}

	r := require.New(t)
	h := newTestHandler(t)
	digest := uniqueDigest(t, "tsa")

	cfg := &v1alpha1.Config{
		RekorURL:        rekorURL(),
		TSAURL:          tsa,
		ForceTSA:        true,
		TrustedRootPath: trustedRootPath(),
	}
	cfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))

	key := mustECDSAKey(t)
	sigInfo, err := h.Sign(t.Context(), digest, cfg, map[string]string{
		credPrivateKeyPEM: pemEncodePrivateKey(t, key),
	})
	r.NoError(err)

	bundle := decodeBundle(t, sigInfo)
	vm := bundle.GetVerificationMaterial()
	r.NotNil(vm)
	r.NotEmpty(vm.GetTimestampVerificationData().GetRfc3161Timestamps(),
		"bundle should contain RFC 3161 timestamps when TSA is configured")

	signed := descruntime.Signature{
		Name:      "integration-tsa-test",
		Digest:    digest,
		Signature: sigInfo,
	}

	err = h.Verify(t.Context(), signed, cfg, map[string]string{
		credPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
	})
	r.NoError(err, "verification with TSA timestamps should succeed")
}

// --------------------------------------------------------------------------
// Rekor v2 integration (Req 2)
// --------------------------------------------------------------------------

func Test_Integration_RekorV2_SignVerify(t *testing.T) {
	skipUnlessIntegration(t)

	if os.Getenv("SIGSTORE_REKOR_V2") != "1" {
		t.Skip("skipping Rekor v2 test: set SIGSTORE_REKOR_V2=1 when a v2 Rekor is available")
	}

	r := require.New(t)
	h := newTestHandler(t)
	digest := uniqueDigest(t, "rekor-v2")

	v2URL := rekorV2URL()
	t.Logf("Rekor v2 URL: %s", v2URL)

	signCfg := &v1alpha1.Config{
		RekorURL:     v2URL,
		RekorVersion: 2,
	}
	signCfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))

	key := mustECDSAKey(t)
	sigInfo, err := h.Sign(t.Context(), digest, signCfg, map[string]string{
		credPrivateKeyPEM: pemEncodePrivateKey(t, key),
	})
	r.NoError(err, "signing with Rekor v2 should succeed")

	bundle := decodeBundle(t, sigInfo)
	r.NotEmpty(bundle.GetVerificationMaterial().GetTlogEntries())

	signed := descruntime.Signature{
		Name:      "integration-rekor-v2",
		Digest:    digest,
		Signature: sigInfo,
	}

	verifyCfg := &v1alpha1.Config{
		RekorURL:        v2URL,
		RekorVersion:    2,
		TrustedRootPath: rekorV2TrustedRootPath(),
	}
	verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))

	err = h.Verify(t.Context(), signed, verifyCfg, map[string]string{
		credPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
	})
	r.NoError(err, "verification with Rekor v2 should succeed")
}

// --------------------------------------------------------------------------
// SigningConfig (Req 3) integration
// --------------------------------------------------------------------------

// signingConfigPath returns the path to a signing_config.json file.
// If SIGSTORE_SIGNING_CONFIG_PATH is set, it is used directly.
// Otherwise a temporary signing_config.json is generated from the
// SIGSTORE_REKOR_URL and SIGSTORE_FULCIO_URL env vars so the test
// can run without the Kind setup script.
func signingConfigPath(t *testing.T) string {
	t.Helper()

	if p := os.Getenv("SIGSTORE_SIGNING_CONFIG_PATH"); p != "" {
		return p
	}

	rURL := rekorURL()
	fURL := fulcioURL()

	const signingConfigTemplate = `{
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

	content := fmt.Sprintf(signingConfigTemplate, fURL, rURL)
	p := filepath.Join(t.TempDir(), "signing_config.json")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))

	t.Logf("Generated signing_config.json at %s (fulcio=%s, rekor=%s)", p, fURL, rURL)
	return p
}

func Test_Integration_SigningConfig(t *testing.T) {
	skipUnlessIntegration(t)
	r := require.New(t)

	h := newTestHandler(t)
	digest := uniqueDigest(t, "signing-config")
	scPath := signingConfigPath(t)

	cfg := &v1alpha1.Config{
		SigningConfigPath: scPath,
	}
	cfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))

	key := mustECDSAKey(t)
	sigInfo, err := h.Sign(t.Context(), digest, cfg, map[string]string{
		credPrivateKeyPEM: pemEncodePrivateKey(t, key),
	})
	r.NoError(err, "signing via signing_config.json should succeed")

	bundle := decodeBundle(t, sigInfo)
	r.NotEmpty(bundle.GetVerificationMaterial().GetTlogEntries(),
		"signing config should route to a Rekor instance")

	signed := descruntime.Signature{
		Name:      "integration-signing-config",
		Digest:    digest,
		Signature: sigInfo,
	}

	verifyCfg := &v1alpha1.Config{
		TrustedRootPath: trustedRootPath(),
	}
	verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))

	err = h.Verify(t.Context(), signed, verifyCfg, map[string]string{
		credPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
	})
	r.NoError(err, "verification after signing_config-based signing should succeed")
}

// --------------------------------------------------------------------------
// TUF-based trusted root resolution (Req 5)
// --------------------------------------------------------------------------

// Test_Integration_TUF_TrustedRoot verifies that the handler can resolve
// trusted material via a TUF mirror (cfg.TUFRootURL) instead of requiring
// a local trusted_root.json file. This exercises the TUF code path in
// resolveTrustedRoot().
func Test_Integration_TUF_TrustedRoot(t *testing.T) {
	skipUnlessIntegration(t)

	tufURL := tufMirrorURL()
	if tufURL == "" {
		t.Skip("skipping TUF test: SIGSTORE_TUF_MIRROR_URL not set")
	}

	r := require.New(t)
	h := newTestHandler(t)
	digest := uniqueDigest(t, "tuf-root")

	// Sign with Rekor (key-based) using the standard config.
	signCfg := configWithRekor(t)
	key := mustECDSAKey(t)
	sigInfo, err := h.Sign(t.Context(), digest, signCfg, map[string]string{
		credPrivateKeyPEM: pemEncodePrivateKey(t, key),
	})
	r.NoError(err, "signing should succeed")

	signed := descruntime.Signature{
		Name:      "integration-tuf-root",
		Digest:    digest,
		Signature: sigInfo,
	}

	// Verify using TUFRootURL instead of TrustedRootPath.
	// This forces the handler to fetch the trusted root from the TUF server
	// rather than reading it from a local file.
	verifyCfg := &v1alpha1.Config{
		TUFRootURL: tufURL,
	}
	verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))

	err = h.Verify(t.Context(), signed, verifyCfg, map[string]string{
		credPublicKeyPEM: pemEncodePublicKey(t, &key.PublicKey),
	})
	r.NoError(err, "verification via TUF trusted root should succeed")
}

// --------------------------------------------------------------------------
// Keyless + Rekor v2 (Req 6)
// --------------------------------------------------------------------------

// Test_Integration_Keyless_RekorV2 performs a keyless signing flow using
// Fulcio (from the Kind cluster) and Rekor v2 (from docker compose).
//
// This requires:
//   - SIGSTORE_REKOR_V2=1
//   - SIGSTORE_REKOR_V2_URL (Rekor v2 HTTP endpoint)
//   - SIGSTORE_REKOR_V2_TRUSTED_ROOT_PATH (composite trusted root with
//     Fulcio CA certs + Rekor v2 log key)
//   - SIGSTORE_OIDC_TOKEN (Kubernetes OIDC token)
//   - SIGSTORE_FULCIO_URL (Fulcio endpoint from Kind cluster)
func Test_Integration_Keyless_RekorV2(t *testing.T) {
	skipUnlessIntegration(t)

	if os.Getenv("SIGSTORE_REKOR_V2") != "1" {
		t.Skip("skipping: set SIGSTORE_REKOR_V2=1 when Rekor v2 is available")
	}

	token := oidcToken()
	if token == "" {
		t.Skip("skipping: SIGSTORE_OIDC_TOKEN not set")
	}

	v2RootPath := rekorV2TrustedRootPath()
	if v2RootPath == "" {
		t.Skip("skipping: SIGSTORE_REKOR_V2_TRUSTED_ROOT_PATH not set")
	}

	r := require.New(t)
	h := newTestHandler(t)
	digest := uniqueDigest(t, "keyless-rekor-v2")

	v2URL := rekorV2URL()
	t.Logf("Rekor v2 URL: %s, Fulcio URL: %s", v2URL, fulcioURL())

	// Keyless + Rekor v2 requires TSA: Rekor v2 does not produce signed entry
	// timestamps (SETs), so without a TSA there is no timestamp to establish
	// Fulcio certificate validity. Signing must include TSA to produce an
	// RFC 3161 signed timestamp.
	tsaURL := tsaURL()
	if tsaURL == "" {
		t.Skip("skipping: keyless + Rekor v2 requires TSA (SIGSTORE_TSA_URL)")
	}

	signCfg := &v1alpha1.Config{
		FulcioURL:    fulcioURL(),
		RekorURL:     v2URL,
		RekorVersion: 2,
		TSAURL:       tsaURL,
	}
	signCfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))

	sigInfo, err := h.Sign(t.Context(), digest, signCfg, map[string]string{
		credOIDCToken: token,
	})
	r.NoError(err, "keyless signing with Fulcio + Rekor v2 should succeed")

	r.Equal(v1alpha1.AlgorithmSigstore, sigInfo.Algorithm)
	r.NotEmpty(sigInfo.Issuer, "keyless signature should have OIDC issuer")

	bundle := decodeBundle(t, sigInfo)
	vm := bundle.GetVerificationMaterial()
	r.NotNil(vm.GetCertificate(), "keyless bundle should contain Fulcio certificate")
	r.NotEmpty(vm.GetTlogEntries(), "bundle should have Rekor v2 tlog entry")

	signed := descruntime.Signature{
		Name:      "integration-keyless-rekor-v2",
		Digest:    digest,
		Signature: sigInfo,
	}

	// Verify using the composite trusted root (Fulcio CA + Rekor v2 key + TSA).
	// ForceTSA tells the verifier to require a signed timestamp instead of
	// integrated timestamps (which Rekor v2 does not produce).
	verifyCfg := &v1alpha1.Config{
		RekorVersion:        2,
		TrustedRootPath:     v2RootPath,
		ForceTSA:            true,
		ExpectedSANRegex:    ".*",
		ExpectedIssuerRegex: ".*",
	}
	verifyCfg.SetType(runtime.NewVersionedType(v1alpha1.ConfigType, v1alpha1.Version))

	err = h.Verify(t.Context(), signed, verifyCfg, map[string]string{
		credTrustedRootJSONFile: v2RootPath,
	})
	r.NoError(err, "keyless verification with Fulcio + Rekor v2 should succeed")
}
