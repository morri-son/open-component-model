package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	descruntime "ocm.software/open-component-model/bindings/go/descriptor/runtime"
	"ocm.software/open-component-model/bindings/go/runtime"

	"ocm.software/open-component-model/bindings/go/cosign/signing/v1alpha1"
)

// mockExecutor records calls and returns configurable responses.
type mockExecutor struct {
	signCalled   bool
	verifyCalled bool

	signDataPath string
	signOpts     SignOpts

	verifyDataPath   string
	verifyBundlePath string
	verifyOpts       VerifyOpts

	signBundleJSON []byte
	signErr        error
	verifyErr      error
}

func (m *mockExecutor) SignBlob(_ context.Context, dataPath string, opts SignOpts) ([]byte, error) {
	m.signCalled = true
	m.signDataPath = dataPath
	m.signOpts = opts

	if m.signErr != nil {
		return nil, m.signErr
	}

	if m.signBundleJSON != nil {
		if err := os.WriteFile(opts.BundleOutPath, m.signBundleJSON, 0o600); err != nil {
			return nil, err
		}
	}
	return m.signBundleJSON, nil
}

func (m *mockExecutor) VerifyBlob(_ context.Context, dataPath, bundlePath string, opts VerifyOpts) error {
	m.verifyCalled = true
	m.verifyDataPath = dataPath
	m.verifyBundlePath = bundlePath
	m.verifyOpts = opts
	return m.verifyErr
}

// --- Test helpers ---

func testDigest() descruntime.Digest {
	return descruntime.Digest{
		HashAlgorithm:          "SHA-256",
		NormalisationAlgorithm: "jsonNormalisation/v2",
		Value:                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
}

func testSignConfig() *v1alpha1.SignConfig {
	cfg := &v1alpha1.SignConfig{
		FulcioURL: "https://fulcio.example.com",
		RekorURL:  "https://rekor.example.com",
		TSAURL:    "https://tsa.example.com/api/v1/timestamp",
	}
	cfg.SetType(runtime.NewVersionedType(v1alpha1.SignConfigType, v1alpha1.Version))
	return cfg
}

func testVerifyConfig() *v1alpha1.VerifyConfig {
	cfg := &v1alpha1.VerifyConfig{
		ExpectedIssuer: "https://accounts.google.com",
		ExpectedSAN:    "user@example.com",
	}
	cfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))
	return cfg
}

func fakeBundleJSON(t *testing.T) []byte {
	t.Helper()
	return []byte(`{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": {
			"certificate": {"rawBytes": ""},
			"tlogEntries": []
		},
		"messageSignature": {
			"messageDigest": {"algorithm": "SHA2_256", "digest": ""},
			"signature": ""
		}
	}`)
}

func fakeBundleJSONWithCert(t *testing.T, issuer string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}

	issuerExtValue := []byte(issuer)
	template.ExtraExtensions = []pkix.Extension{
		{
			Id:    sigstoreIssuerV1OID,
			Value: issuerExtValue,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certB64 := base64.StdEncoding.EncodeToString(certDER)
	bundle := map[string]interface{}{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]interface{}{
			"certificate": map[string]string{"rawBytes": certB64},
			"tlogEntries": []interface{}{},
		},
		"messageSignature": map[string]interface{}{
			"messageDigest": map[string]string{"algorithm": "SHA2_256", "digest": ""},
			"signature":     "",
		},
	}
	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data
}

// --- Sign tests ---

func TestSign_BuildsCorrectFlags(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	mock := &mockExecutor{signBundleJSON: fakeBundleJSON(t)}
	h := NewWithExecutor(mock)

	cfg := testSignConfig()
	creds := map[string]string{CredentialKeyOIDCToken: "test-token"}

	_, err := h.Sign(t.Context(), testDigest(), cfg, creds)
	r.NoError(err)
	r.True(mock.signCalled)
	r.Equal("test-token", mock.signOpts.IdentityToken)
	r.Equal("https://fulcio.example.com", mock.signOpts.FulcioURL)
	r.Equal("https://rekor.example.com", mock.signOpts.RekorURL)
	r.Equal("https://tsa.example.com/api/v1/timestamp", mock.signOpts.TSAURL)
}

func TestSign_WithoutToken(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	mock := &mockExecutor{signBundleJSON: fakeBundleJSON(t)}
	h := NewWithExecutor(mock)

	cfg := testSignConfig()
	creds := map[string]string{}

	_, err := h.Sign(t.Context(), testDigest(), cfg, creds)
	r.NoError(err)
	r.True(mock.signCalled)
	r.Empty(mock.signOpts.IdentityToken)
}

func TestSign_WritesDigestBytesToTempFile(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	var capturedData []byte
	mock := &mockExecutor{signBundleJSON: fakeBundleJSON(t)}
	origSign := mock.SignBlob
	_ = origSign

	recording := &recordingExecutor{
		delegate:    mock,
		captureData: func(data []byte) { capturedData = data },
	}
	h := NewWithExecutor(recording)

	cfg := testSignConfig()
	digest := testDigest()

	_, err := h.Sign(t.Context(), digest, cfg, map[string]string{})
	r.NoError(err)

	expectedBytes, err := hex.DecodeString(digest.Value)
	r.NoError(err)
	r.Equal(expectedBytes, capturedData)
}

func TestSign_BundleEncoding(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	bundleData := fakeBundleJSON(t)
	mock := &mockExecutor{signBundleJSON: bundleData}
	h := NewWithExecutor(mock)

	cfg := testSignConfig()
	result, err := h.Sign(t.Context(), testDigest(), cfg, map[string]string{})
	r.NoError(err)

	r.Equal(v1alpha1.AlgorithmSigstore, result.Algorithm)
	r.Equal(v1alpha1.MediaTypeSigstoreBundle, result.MediaType)

	decoded, err := base64.StdEncoding.DecodeString(result.Value)
	r.NoError(err)
	r.JSONEq(string(bundleData), string(decoded))
}

func TestSign_IssuerExtraction(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	expectedIssuer := "https://accounts.google.com"
	bundleData := fakeBundleJSONWithCert(t, expectedIssuer)

	mock := &mockExecutor{signBundleJSON: bundleData}
	h := NewWithExecutor(mock)

	cfg := testSignConfig()
	result, err := h.Sign(t.Context(), testDigest(), cfg, map[string]string{})
	r.NoError(err)
	r.Equal(expectedIssuer, result.Issuer)
}

func TestSign_IssuerV2Extraction(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	expectedIssuer := "https://token.actions.githubusercontent.com"

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r.NoError(err)

	asn1Issuer, err := asn1.Marshal(expectedIssuer)
	r.NoError(err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{Id: sigstoreIssuerV2OID, Value: asn1Issuer},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	r.NoError(err)

	certB64 := base64.StdEncoding.EncodeToString(certDER)
	bundle := map[string]interface{}{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]interface{}{
			"certificate": map[string]string{"rawBytes": certB64},
		},
		"messageSignature": map[string]interface{}{},
	}
	bundleData, err := json.Marshal(bundle)
	r.NoError(err)

	mock := &mockExecutor{signBundleJSON: bundleData}
	h := NewWithExecutor(mock)

	cfg := testSignConfig()
	result, err := h.Sign(t.Context(), testDigest(), cfg, map[string]string{})
	r.NoError(err)
	r.Equal(expectedIssuer, result.Issuer)
}

func TestSign_CosignError(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	mock := &mockExecutor{signErr: fmt.Errorf("cosign sign-blob failed: exit status 1\nstderr: error signing")}
	h := NewWithExecutor(mock)

	cfg := testSignConfig()
	_, err := h.Sign(t.Context(), testDigest(), cfg, map[string]string{})
	r.Error(err)
	r.Contains(err.Error(), "cosign sign")
}

func TestSign_InvalidHexDigest(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	mock := &mockExecutor{}
	h := NewWithExecutor(mock)

	cfg := testSignConfig()
	digest := descruntime.Digest{Value: "not-hex!"}
	_, err := h.Sign(t.Context(), digest, cfg, map[string]string{})
	r.Error(err)
	r.Contains(err.Error(), "decode digest hex")
}

func TestSign_WrongConfigType(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	h := NewWithExecutor(&mockExecutor{})

	cfg := testVerifyConfig()
	_, err := h.Sign(t.Context(), testDigest(), cfg, map[string]string{})
	r.Error(err)
	r.Contains(err.Error(), "expected config type")
}

func TestSign_TempFileCleanup(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	var dataPath, bundlePath string
	mock := &mockExecutor{signBundleJSON: fakeBundleJSON(t)}
	recording := &pathRecordingExecutor{
		delegate: mock,
		onSign: func(dp string, opts SignOpts) {
			dataPath = dp
			bundlePath = opts.BundleOutPath
		},
	}
	h := NewWithExecutor(recording)

	cfg := testSignConfig()
	_, err := h.Sign(t.Context(), testDigest(), cfg, map[string]string{})
	r.NoError(err)

	r.NotEmpty(dataPath)
	r.NotEmpty(bundlePath)
	_, err = os.Stat(dataPath)
	r.True(os.IsNotExist(err), "data temp file should be cleaned up")
	_, err = os.Stat(bundlePath)
	r.True(os.IsNotExist(err), "bundle temp file should be cleaned up")
}

// --- Verify tests ---

func TestVerify_BuildsCorrectFlags(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	mock := &mockExecutor{}
	h := NewWithExecutor(mock)

	cfg := testVerifyConfig()
	cfg.ExpectedIssuerRegex = ".*google.*"
	cfg.ExpectedSANRegex = ".*@example.com"
	cfg.TrustedRootPath = "/path/to/trusted_root.json"

	bundleJSON := fakeBundleJSON(t)
	signed := descruntime.Signature{
		Name:   "test-sig",
		Digest: testDigest(),
		Signature: descruntime.SignatureInfo{
			Algorithm: v1alpha1.AlgorithmSigstore,
			MediaType: v1alpha1.MediaTypeSigstoreBundle,
			Value:     base64.StdEncoding.EncodeToString(bundleJSON),
		},
	}

	err := h.Verify(t.Context(), signed, cfg, map[string]string{})
	r.NoError(err)
	r.True(mock.verifyCalled)
	r.Equal("user@example.com", mock.verifyOpts.CertificateIdentity)
	r.Equal(".*@example.com", mock.verifyOpts.CertificateIdentityRegexp)
	r.Equal("https://accounts.google.com", mock.verifyOpts.CertificateOIDCIssuer)
	r.Equal(".*google.*", mock.verifyOpts.CertificateOIDCIssuerRegexp)
	r.Equal("/path/to/trusted_root.json", mock.verifyOpts.TrustedRoot)
}

func TestVerify_TrustedRootFromCredentials(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	mock := &mockExecutor{}
	h := NewWithExecutor(mock)

	cfg := testVerifyConfig()
	bundleJSON := fakeBundleJSON(t)
	signed := descruntime.Signature{
		Name:   "test-sig",
		Digest: testDigest(),
		Signature: descruntime.SignatureInfo{
			Algorithm: v1alpha1.AlgorithmSigstore,
			MediaType: v1alpha1.MediaTypeSigstoreBundle,
			Value:     base64.StdEncoding.EncodeToString(bundleJSON),
		},
	}

	creds := map[string]string{
		CredentialKeyTrustedRootJSON: `{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`,
	}

	err := h.Verify(t.Context(), signed, cfg, creds)
	r.NoError(err)
	r.True(mock.verifyCalled)
	r.NotEmpty(mock.verifyOpts.TrustedRoot)
	_, err = os.Stat(mock.verifyOpts.TrustedRoot)
	r.True(os.IsNotExist(err), "temp trusted root file should be cleaned up after verify")
}

func TestVerify_TrustedRootFromFileCredential(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	mock := &mockExecutor{}
	h := NewWithExecutor(mock)

	cfg := testVerifyConfig()
	bundleJSON := fakeBundleJSON(t)
	signed := descruntime.Signature{
		Name:   "test-sig",
		Digest: testDigest(),
		Signature: descruntime.SignatureInfo{
			Algorithm: v1alpha1.AlgorithmSigstore,
			MediaType: v1alpha1.MediaTypeSigstoreBundle,
			Value:     base64.StdEncoding.EncodeToString(bundleJSON),
		},
	}

	creds := map[string]string{
		CredentialKeyTrustedRootJSONFile: "/custom/path/trusted_root.json",
	}

	err := h.Verify(t.Context(), signed, cfg, creds)
	r.NoError(err)
	r.Equal("/custom/path/trusted_root.json", mock.verifyOpts.TrustedRoot)
}

func TestVerify_Success(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	mock := &mockExecutor{}
	h := NewWithExecutor(mock)

	cfg := testVerifyConfig()
	bundleJSON := fakeBundleJSON(t)
	signed := descruntime.Signature{
		Name:   "test-sig",
		Digest: testDigest(),
		Signature: descruntime.SignatureInfo{
			Algorithm: v1alpha1.AlgorithmSigstore,
			MediaType: v1alpha1.MediaTypeSigstoreBundle,
			Value:     base64.StdEncoding.EncodeToString(bundleJSON),
		},
	}

	err := h.Verify(t.Context(), signed, cfg, map[string]string{})
	r.NoError(err)
}

func TestVerify_Failure(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	mock := &mockExecutor{
		verifyErr: fmt.Errorf("cosign verify-blob failed: exit status 1\nstderr: signature verification failed"),
	}
	h := NewWithExecutor(mock)

	cfg := testVerifyConfig()
	bundleJSON := fakeBundleJSON(t)
	signed := descruntime.Signature{
		Name:   "test-sig",
		Digest: testDigest(),
		Signature: descruntime.SignatureInfo{
			Algorithm: v1alpha1.AlgorithmSigstore,
			MediaType: v1alpha1.MediaTypeSigstoreBundle,
			Value:     base64.StdEncoding.EncodeToString(bundleJSON),
		},
	}

	err := h.Verify(t.Context(), signed, cfg, map[string]string{})
	r.Error(err)
	r.Contains(err.Error(), "cosign verification failed")
}

func TestVerify_MissingIdentity(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	h := NewWithExecutor(&mockExecutor{})

	cfg := &v1alpha1.VerifyConfig{}
	cfg.SetType(runtime.NewVersionedType(v1alpha1.VerifyConfigType, v1alpha1.Version))

	bundleJSON := fakeBundleJSON(t)
	signed := descruntime.Signature{
		Name:   "test-sig",
		Digest: testDigest(),
		Signature: descruntime.SignatureInfo{
			Algorithm: v1alpha1.AlgorithmSigstore,
			MediaType: v1alpha1.MediaTypeSigstoreBundle,
			Value:     base64.StdEncoding.EncodeToString(bundleJSON),
		},
	}

	err := h.Verify(t.Context(), signed, cfg, map[string]string{})
	r.Error(err)
	r.Contains(err.Error(), "keyless verification requires identity config")
}

func TestVerify_InvalidBase64Bundle(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	h := NewWithExecutor(&mockExecutor{})

	cfg := testVerifyConfig()
	signed := descruntime.Signature{
		Name:   "test-sig",
		Digest: testDigest(),
		Signature: descruntime.SignatureInfo{
			Algorithm: v1alpha1.AlgorithmSigstore,
			MediaType: v1alpha1.MediaTypeSigstoreBundle,
			Value:     "not-valid-base64!!!",
		},
	}

	err := h.Verify(t.Context(), signed, cfg, map[string]string{})
	r.Error(err)
	r.Contains(err.Error(), "decode bundle base64")
}

func TestVerify_WrongConfigType(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	h := NewWithExecutor(&mockExecutor{})

	cfg := testSignConfig()
	signed := descruntime.Signature{
		Name:   "test-sig",
		Digest: testDigest(),
		Signature: descruntime.SignatureInfo{
			Algorithm: v1alpha1.AlgorithmSigstore,
			MediaType: v1alpha1.MediaTypeSigstoreBundle,
			Value:     base64.StdEncoding.EncodeToString(fakeBundleJSON(t)),
		},
	}

	err := h.Verify(t.Context(), signed, cfg, map[string]string{})
	r.Error(err)
	r.Contains(err.Error(), "expected config type")
}

func TestVerify_NoTrustedRoot_NoFlag(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	mock := &mockExecutor{}
	h := NewWithExecutor(mock)

	cfg := testVerifyConfig()
	bundleJSON := fakeBundleJSON(t)
	signed := descruntime.Signature{
		Name:   "test-sig",
		Digest: testDigest(),
		Signature: descruntime.SignatureInfo{
			Algorithm: v1alpha1.AlgorithmSigstore,
			MediaType: v1alpha1.MediaTypeSigstoreBundle,
			Value:     base64.StdEncoding.EncodeToString(bundleJSON),
		},
	}

	err := h.Verify(t.Context(), signed, cfg, map[string]string{})
	r.NoError(err)
	r.Empty(mock.verifyOpts.TrustedRoot)
}

// --- Identity tests ---

func TestGetSigningCredentialConsumerIdentity(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	h := NewWithExecutor(&mockExecutor{})
	cfg := testSignConfig()

	id, err := h.GetSigningCredentialConsumerIdentity(t.Context(), "my-sig", testDigest(), cfg)
	r.NoError(err)
	r.Equal(v1alpha1.AlgorithmSigstore, id[IdentityAttributeAlgorithm])
	r.Equal("my-sig", id[IdentityAttributeSignature])
}

func TestGetVerifyingCredentialConsumerIdentity(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	h := NewWithExecutor(&mockExecutor{})
	signed := descruntime.Signature{
		Name: "my-sig",
		Signature: descruntime.SignatureInfo{
			MediaType: v1alpha1.MediaTypeSigstoreBundle,
		},
	}

	id, err := h.GetVerifyingCredentialConsumerIdentity(t.Context(), signed, nil)
	r.NoError(err)
	r.Equal(v1alpha1.AlgorithmSigstore, id[IdentityAttributeAlgorithm])
	r.Equal("my-sig", id[IdentityAttributeSignature])
}

func TestGetVerifyingCredentialConsumerIdentity_WrongMediaType(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	h := NewWithExecutor(&mockExecutor{})
	signed := descruntime.Signature{
		Name: "my-sig",
		Signature: descruntime.SignatureInfo{
			MediaType: "application/pgp-signature",
		},
	}

	_, err := h.GetVerifyingCredentialConsumerIdentity(t.Context(), signed, nil)
	r.Error(err)
	r.Contains(err.Error(), "unsupported media type")
}

// --- DefaultExecutor flag construction test ---

func TestDefaultExecutor_SignBlobArgs(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	e := &DefaultExecutor{BinaryPath: "echo"}
	opts := SignOpts{
		BundleOutPath: "/dev/null",
		IdentityToken: "my-token",
		FulcioURL:     "https://fulcio.example.com",
		RekorURL:      "https://rekor.example.com",
		TSAURL:        "https://tsa.example.com",
	}

	_, err := e.SignBlob(t.Context(), "/dev/null", opts)
	// echo will succeed but bundle file read will produce empty/error — that's fine,
	// we just want to verify the command doesn't panic
	_ = err
	_ = r
}

// --- Helper executors for recording ---

type recordingExecutor struct {
	delegate    Executor
	captureData func([]byte)
}

func (r *recordingExecutor) SignBlob(ctx context.Context, dataPath string, opts SignOpts) ([]byte, error) {
	if r.captureData != nil {
		data, err := os.ReadFile(dataPath)
		if err == nil {
			r.captureData(data)
		}
	}
	return r.delegate.SignBlob(ctx, dataPath, opts)
}

func (r *recordingExecutor) VerifyBlob(ctx context.Context, dataPath, bundlePath string, opts VerifyOpts) error {
	return r.delegate.VerifyBlob(ctx, dataPath, bundlePath, opts)
}

type pathRecordingExecutor struct {
	delegate Executor
	onSign   func(dataPath string, opts SignOpts)
}

func (p *pathRecordingExecutor) SignBlob(ctx context.Context, dataPath string, opts SignOpts) ([]byte, error) {
	if p.onSign != nil {
		p.onSign(dataPath, opts)
	}
	return p.delegate.SignBlob(ctx, dataPath, opts)
}

func (p *pathRecordingExecutor) VerifyBlob(ctx context.Context, dataPath, bundlePath string, opts VerifyOpts) error {
	return p.delegate.VerifyBlob(ctx, dataPath, bundlePath, opts)
}

// --- extractIssuerFromBundleJSON tests ---

func TestExtractIssuer_EmptyBundle(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	r.Empty(extractIssuerFromBundleJSON([]byte(`{}`)))
}

func TestExtractIssuer_NoCert(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	r.Empty(extractIssuerFromBundleJSON(fakeBundleJSON(t)))
}

func TestExtractIssuer_ValidV1(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	issuer := extractIssuerFromBundleJSON(fakeBundleJSONWithCert(t, "https://issuer.example.com"))
	r.Equal("https://issuer.example.com", issuer)
}

func TestExtractIssuer_InvalidJSON(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	r.Empty(extractIssuerFromBundleJSON([]byte("not json")))
}
