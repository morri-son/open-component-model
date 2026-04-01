package handler

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"

	descruntime "ocm.software/open-component-model/bindings/go/descriptor/runtime"
	"ocm.software/open-component-model/bindings/go/runtime"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/handler/internal/credentials"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/v1alpha1"
)

func doSign(
	ctx context.Context,
	unsigned descruntime.Digest,
	cfg *v1alpha1.SignConfig,
	creds map[string]string,
) (descruntime.SignatureInfo, error) {
	if err := validateSignConfig(cfg); err != nil {
		return descruntime.SignatureInfo{}, err
	}

	digestBytes, err := hex.DecodeString(unsigned.Value)
	if err != nil {
		return descruntime.SignatureInfo{}, fmt.Errorf("decode digest hex value: %w", err)
	}

	keypair, idToken, err := resolveKeypair(creds)
	if err != nil {
		return descruntime.SignatureInfo{}, err
	}

	opts := sign.BundleOptions{Context: ctx}

	switch {
	case cfg.SigningConfigPath != "":
		if err := configureFromSigningConfig(&opts, cfg, idToken); err != nil {
			return descruntime.SignatureInfo{}, err
		}
	case hasExplicitEndpoints(cfg):
		if err := configureCertificateProvider(&opts, cfg, idToken); err != nil {
			return descruntime.SignatureInfo{}, err
		}
		configureTimestampAuthority(&opts, cfg)
		configureTransparencyLog(&opts, cfg)
	case idToken != "":
		slog.InfoContext(ctx, "no explicit Sigstore endpoints configured, fetching signing config from public-good TUF")
		sc, err := root.FetchSigningConfig()
		if err != nil {
			return descruntime.SignatureInfo{}, fmt.Errorf("fetch public Sigstore signing config: %w", err)
		}
		if err := applySigningConfig(&opts, sc, idToken); err != nil {
			return descruntime.SignatureInfo{}, err
		}
	default:
		// Key-based signing without explicit endpoints: produce a minimal bundle
		// with only the signature and public key hint (no Fulcio, Rekor, or TSA).
		// This matches cosign's default behavior (--tlog-upload=false since v1.14.0).
		slog.InfoContext(ctx, "key-based signing with no explicit endpoints, producing minimal bundle")
	}

	// When a trusted root is available from an offline source and we are
	// in a keyless flow (Fulcio certificate), set it on BundleOptions so
	// sign.Bundle can verify the created bundle before returning it
	// (defense-in-depth). Key-based bundles use a public-key hint that
	// is not present in the trusted root, so sign-time verification
	// would always fail. TUF is intentionally excluded to avoid a
	// network round-trip at sign time.
	if idToken != "" {
		if tr, err := resolveOfflineTrustedRoot(creds); err != nil {
			slog.WarnContext(ctx, "failed to resolve offline trusted root for sign-time verification", "error", err)
		} else if tr != nil {
			opts.TrustedRoot = tr
		}
	}

	content := &sign.PlainData{Data: digestBytes}

	bundle, err := sign.Bundle(content, keypair, opts)
	if err != nil {
		return descruntime.SignatureInfo{}, fmt.Errorf("create sigstore bundle: %w", err)
	}

	bundleJSON, err := protojson.Marshal(bundle)
	if err != nil {
		return descruntime.SignatureInfo{}, fmt.Errorf("marshal sigstore bundle: %w", err)
	}

	issuer := extractIssuer(bundle)

	return descruntime.SignatureInfo{
		Algorithm: v1alpha1.AlgorithmSigstore,
		MediaType: v1alpha1.MediaTypeSigstoreBundle,
		Value:     base64.StdEncoding.EncodeToString(bundleJSON),
		Issuer:    issuer,
	}, nil
}

// resolveKeypair determines the signing keypair and optional OIDC token from credentials.
//
// Two modes are supported (checked in order):
//  1. Key-based: a private key PEM is present in creds. Returns a keypair
//     wrapping that key and an empty OIDC token.
//  2. Keyless: returns an ephemeral keypair and any OIDC token from creds.
//     If no token is available, the returned token is empty — the caller is
//     responsible for ensuring a token is provided through the credential graph
//     (e.g. via the SigstoreOIDC credential plugin).
func resolveKeypair(creds map[string]string) (sign.Keypair, string, error) {
	privKey, err := credentials.PrivateKeyFromCredentials(creds)
	if err != nil {
		return nil, "", fmt.Errorf("load private key: %w", err)
	}

	if privKey != nil {
		kp, err := keypairFromPrivateKey(privKey)
		if err != nil {
			return nil, "", fmt.Errorf("create keypair: %w", err)
		}
		return kp, "", nil
	}

	idToken := credentials.OIDCTokenFromCredentials(creds)

	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, "", fmt.Errorf("create ephemeral keypair: %w", err)
	}
	return keypair, idToken, nil
}

// keypairFromPrivateKey creates the appropriate sign.Keypair implementation for the given key type.
func keypairFromPrivateKey(key crypto.PrivateKey) (sign.Keypair, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return newECDSAKeypair(k)
	case ed25519.PrivateKey:
		return newEd25519Keypair(k)
	default:
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
}

func configureCertificateProvider(opts *sign.BundleOptions, cfg *v1alpha1.SignConfig, idToken string) error {
	if idToken == "" {
		return nil
	}
	if cfg.FulcioURL == "" {
		return fmt.Errorf("FulcioURL must be set for keyless signing (OIDC token provided but no Fulcio endpoint configured)")
	}

	opts.CertificateProvider = sign.NewFulcio(&sign.FulcioOptions{
		BaseURL: cfg.FulcioURL,
	})
	opts.CertificateProviderOptions = &sign.CertificateProviderOptions{
		IDToken: idToken,
	}
	return nil
}

func configureTimestampAuthority(opts *sign.BundleOptions, cfg *v1alpha1.SignConfig) {
	if cfg.TSAURL == "" {
		return
	}
	opts.TimestampAuthorities = append(opts.TimestampAuthorities, sign.NewTimestampAuthority(&sign.TimestampAuthorityOptions{
		URL: cfg.TSAURL,
	}))
}

func configureTransparencyLog(opts *sign.BundleOptions, cfg *v1alpha1.SignConfig) {
	if cfg.RekorURL == "" {
		return
	}
	rekorOpts := &sign.RekorOptions{
		BaseURL: cfg.RekorURL,
	}
	if cfg.RekorVersion != 0 {
		rekorOpts.Version = cfg.RekorVersion
	}
	opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(rekorOpts))
}

// hasExplicitEndpoints returns true when the config contains at least one
// explicitly configured Sigstore service endpoint.
func hasExplicitEndpoints(cfg *v1alpha1.SignConfig) bool {
	return cfg.FulcioURL != "" || cfg.RekorURL != "" || cfg.TSAURL != ""
}

// configureFromSigningConfig loads a signing_config.json and uses it to discover
// Fulcio, Rekor, and TSA endpoints, replacing the individual URL config fields.
func configureFromSigningConfig(opts *sign.BundleOptions, cfg *v1alpha1.SignConfig, idToken string) error {
	sc, err := root.NewSigningConfigFromPath(cfg.SigningConfigPath)
	if err != nil {
		return fmt.Errorf("load signing config: %w", err)
	}
	return applySigningConfig(opts, sc, idToken)
}

// applySigningConfig configures bundle options from a SigningConfig, selecting
// the best available Fulcio, Rekor, and TSA service endpoints.
func applySigningConfig(opts *sign.BundleOptions, sc *root.SigningConfig, idToken string) error {
	now := time.Now()

	if idToken != "" {
		fulcioSvc, err := root.SelectService(sc.FulcioCertificateAuthorityURLs(), sign.FulcioAPIVersions, now)
		if err != nil {
			return fmt.Errorf("select fulcio service: %w", err)
		}
		opts.CertificateProvider = sign.NewFulcio(&sign.FulcioOptions{
			BaseURL: fulcioSvc.URL,
		})
		opts.CertificateProviderOptions = &sign.CertificateProviderOptions{
			IDToken: idToken,
		}
	}

	rekorServices := sc.RekorLogURLs()
	if len(rekorServices) > 0 {
		rekorSvc, err := root.SelectService(rekorServices, sign.RekorAPIVersions, now)
		if err != nil {
			return fmt.Errorf("select rekor service: %w", err)
		}
		opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(&sign.RekorOptions{
			BaseURL: rekorSvc.URL,
			Version: rekorSvc.MajorAPIVersion,
		}))
	}

	tsaServices := sc.TimestampAuthorityURLs()
	if len(tsaServices) > 0 {
		tsaSvc, err := root.SelectService(tsaServices, sign.TimestampAuthorityAPIVersions, now)
		if err != nil {
			return fmt.Errorf("select tsa service: %w", err)
		}
		opts.TimestampAuthorities = append(opts.TimestampAuthorities, sign.NewTimestampAuthority(&sign.TimestampAuthorityOptions{
			URL: tsaSvc.URL,
		}))
	}

	return nil
}

// extractIssuer attempts to extract the OIDC issuer from the Fulcio certificate in the bundle.
// It delegates to sigstore-go's certificate.ParseExtensions which handles both the v2 extension
// (OID 1.3.6.1.4.1.57264.1.8, proper ASN.1 encoding) and the deprecated v1 extension
// (OID 1.3.6.1.4.1.57264.1.1, raw UTF-8 bytes).
func extractIssuer(bundle *protobundle.Bundle) string {
	vm := bundle.GetVerificationMaterial()
	if vm == nil {
		return ""
	}
	certContent := vm.GetCertificate()
	if certContent == nil {
		return ""
	}
	rawBytes := certContent.GetRawBytes()
	if len(rawBytes) == 0 {
		return ""
	}
	cert, err := x509.ParseCertificate(rawBytes)
	if err != nil {
		return ""
	}

	extensions, err := certificate.ParseExtensions(cert.Extensions)
	if err != nil {
		return ""
	}
	return extensions.Issuer
}

// validateSignConfig checks signing config fields for obviously invalid values.
func validateSignConfig(cfg *v1alpha1.SignConfig) error {
	if cfg.RekorVersion > 2 {
		return fmt.Errorf("unsupported RekorVersion %d: must be 0 (default), 1, or 2", cfg.RekorVersion)
	}
	return nil
}

func signWithConfig(
	ctx context.Context,
	unsigned descruntime.Digest,
	rawCfg runtime.Typed,
	creds map[string]string,
	scheme *runtime.Scheme,
) (descruntime.SignatureInfo, error) {
	var cfg v1alpha1.SignConfig
	if err := scheme.Convert(rawCfg, &cfg); err != nil {
		return descruntime.SignatureInfo{}, fmt.Errorf("convert config: %w", err)
	}
	if got := cfg.GetType(); got != (runtime.Type{}) && got.GetName() != v1alpha1.SignConfigType {
		return descruntime.SignatureInfo{}, fmt.Errorf("expected config type %s but got %s", v1alpha1.SignConfigType, got)
	}

	return doSign(ctx, unsigned, &cfg, creds)
}

// ecdsaKeypair adapts an *ecdsa.PrivateKey to sigstore-go's sign.Keypair interface.
// The signing algorithm is selected based on the key's curve (P-256, P-384, P-521),
// using AlgorithmDetails from the sigstore algorithm registry rather than hardcoding values.
type ecdsaKeypair struct {
	privKey    *ecdsa.PrivateKey
	hint       []byte
	algDetails signature.AlgorithmDetails
}

// ecdsaCurveAlgorithm maps ECDSA curves to their corresponding protobuf algorithm constant.
var ecdsaCurveAlgorithm = map[elliptic.Curve]protocommon.PublicKeyDetails{
	elliptic.P256(): protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
	elliptic.P384(): protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384,
	elliptic.P521(): protocommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512,
}

func newECDSAKeypair(privKey *ecdsa.PrivateKey) (*ecdsaKeypair, error) {
	alg, ok := ecdsaCurveAlgorithm[privKey.Curve]
	if !ok {
		return nil, fmt.Errorf("unsupported ECDSA curve %s", privKey.Curve.Params().Name)
	}
	algDetails, err := signature.GetAlgorithmDetails(alg)
	if err != nil {
		return nil, fmt.Errorf("get algorithm details: %w", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal public key to DER: %w", err)
	}
	hashedBytes := sha256.Sum256(pubKeyBytes)
	hint := []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))

	return &ecdsaKeypair{privKey: privKey, hint: hint, algDetails: algDetails}, nil
}

func (k *ecdsaKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return k.algDetails.GetProtoHashType()
}

func (k *ecdsaKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return k.algDetails.GetSignatureAlgorithm()
}

func (k *ecdsaKeypair) GetHint() []byte {
	return k.hint
}

func (k *ecdsaKeypair) GetKeyAlgorithm() string {
	return "ECDSA"
}

func (k *ecdsaKeypair) GetPublicKey() crypto.PublicKey {
	return k.privKey.Public()
}

func (k *ecdsaKeypair) GetPublicKeyPem() (string, error) {
	pem, err := cryptoutils.MarshalPublicKeyToPEM(k.privKey.Public())
	if err != nil {
		return "", err
	}
	return string(pem), nil
}

func (k *ecdsaKeypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	hf := k.algDetails.GetHashType()
	hasher := hf.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)
	sig, err := k.privKey.Sign(rand.Reader, digest, hf)
	if err != nil {
		return nil, nil, err
	}
	return sig, digest, nil
}

// ed25519Keypair adapts an ed25519.PrivateKey to sigstore-go's sign.Keypair interface.
// Ed25519 performs its own internal hashing (using SHA-512), so SignData passes
// the raw data directly to the signer without pre-hashing.
type ed25519Keypair struct {
	privKey ed25519.PrivateKey
	hint    []byte
}

func newEd25519Keypair(privKey ed25519.PrivateKey) (*ed25519Keypair, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal public key to DER: %w", err)
	}
	hashedBytes := sha256.Sum256(pubKeyBytes)
	hint := []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))
	return &ed25519Keypair{privKey: privKey, hint: hint}, nil
}

func (k *ed25519Keypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	// Ed25519 uses SHA-512 internally; no separate pre-hashing is performed.
	return protocommon.HashAlgorithm_SHA2_512
}

func (k *ed25519Keypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return protocommon.PublicKeyDetails_PKIX_ED25519
}

func (k *ed25519Keypair) GetHint() []byte {
	return k.hint
}

func (k *ed25519Keypair) GetKeyAlgorithm() string {
	return "Ed25519"
}

func (k *ed25519Keypair) GetPublicKey() crypto.PublicKey {
	return k.privKey.Public()
}

func (k *ed25519Keypair) GetPublicKeyPem() (string, error) {
	pem, err := cryptoutils.MarshalPublicKeyToPEM(k.privKey.Public())
	if err != nil {
		return "", err
	}
	return string(pem), nil
}

// SignData signs data with Ed25519. Unlike ECDSA, Ed25519 does not accept a
// pre-computed digest; it hashes internally. The returned digest is the raw
// data (not a hash), matching sigstore-go's expectation for PKIX_ED25519.
func (k *ed25519Keypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	sig, err := k.privKey.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		return nil, nil, err
	}
	return sig, data, nil
}
