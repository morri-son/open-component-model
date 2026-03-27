package handler

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/encoding/protojson"

	descruntime "ocm.software/open-component-model/bindings/go/descriptor/runtime"
	"ocm.software/open-component-model/bindings/go/runtime"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/handler/internal/credentials"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/v1alpha1"
)

const (
	defaultFulcioURL = "https://fulcio.sigstore.dev"
	defaultRekorURL  = "https://rekor.sigstore.dev"
	defaultTSAURL    = "https://timestamp.sigstore.dev"
	defaultTimeout   = 30 * time.Second
	// defaultRekorTimeout is intentionally longer than defaultTimeout because
	// Rekor may need extra time for inclusion proof computation and log
	// consistency checks, especially under high load or when using Rekor v2
	// tile-backed logs.
	defaultRekorTimeout = 90 * time.Second
)

func doSign(
	ctx context.Context,
	unsigned descruntime.Digest,
	cfg *v1alpha1.Config,
	creds map[string]string,
) (descruntime.SignatureInfo, error) {
	digestBytes, err := hex.DecodeString(unsigned.Value)
	if err != nil {
		return descruntime.SignatureInfo{}, fmt.Errorf("decode digest hex value: %w", err)
	}

	keypair, idToken, err := resolveKeypair(creds)
	if err != nil {
		return descruntime.SignatureInfo{}, err
	}

	opts := sign.BundleOptions{Context: ctx}

	if cfg.SigningConfigPath != "" {
		if err := configureFromSigningConfig(&opts, cfg, idToken); err != nil {
			return descruntime.SignatureInfo{}, err
		}
	} else {
		if err := configureCertificateProvider(&opts, cfg, idToken); err != nil {
			return descruntime.SignatureInfo{}, err
		}
		configureTimestampAuthority(&opts, cfg)
		configureTransparencyLog(&opts, cfg)
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
// Three modes are supported:
//  1. Key-based: a private key PEM is present in creds. Returns an ecdsaKeypair
//     wrapping that key and an empty OIDC token.
//  2. Keyless (OIDC): no private key but an OIDC token is present. Returns an
//     ephemeral keypair (for Fulcio certificate issuance) and the token.
//  3. Ephemeral (offline): neither private key nor OIDC token. Returns an
//     ephemeral keypair with an empty token. Bundles produced in this mode
//     contain only a public key hint and no Fulcio certificate.
func resolveKeypair(creds map[string]string) (sign.Keypair, string, error) {
	privKey, err := credentials.PrivateKeyFromCredentials(creds)
	if err != nil {
		return nil, "", fmt.Errorf("load private key: %w", err)
	}

	if privKey != nil {
		kp, err := newECDSAKeypair(privKey)
		if err != nil {
			return nil, "", fmt.Errorf("create ECDSA keypair: %w", err)
		}
		return kp, "", nil
	}

	idToken := credentials.OIDCTokenFromCredentials(creds)
	if idToken == "" {
		idToken = os.Getenv("SIGSTORE_ID_TOKEN")
	}
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, "", fmt.Errorf("create ephemeral keypair: %w", err)
	}
	return keypair, idToken, nil
}

func configureCertificateProvider(opts *sign.BundleOptions, cfg *v1alpha1.Config, idToken string) error {
	if idToken == "" {
		return nil
	}
	url := cfg.FulcioURL
	if url == "" {
		url = defaultFulcioURL
	}

	opts.CertificateProvider = sign.NewFulcio(&sign.FulcioOptions{
		BaseURL: url,
		Timeout: defaultTimeout,
		Retries: 1,
	})
	opts.CertificateProviderOptions = &sign.CertificateProviderOptions{
		IDToken: idToken,
	}
	return nil
}

func configureTimestampAuthority(opts *sign.BundleOptions, cfg *v1alpha1.Config) {
	if cfg.TSAURL == "" && !cfg.ForceTSA {
		return
	}
	tsaURL := cfg.TSAURL
	if tsaURL == "" {
		tsaURL = defaultTSAURL
	}
	tsaURL = ensureTSAPath(tsaURL)
	opts.TimestampAuthorities = append(opts.TimestampAuthorities, sign.NewTimestampAuthority(&sign.TimestampAuthorityOptions{
		URL:     tsaURL,
		Timeout: defaultTimeout,
		Retries: 1,
	}))
}

// ensureTSAPath appends the standard RFC 3161 API path if the URL does not
// already contain a path component beyond "/".
func ensureTSAPath(rawURL string) string {
	const tsaPath = "/api/v1/timestamp"
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL + tsaPath
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = tsaPath
		return u.String()
	}
	return rawURL
}

func configureTransparencyLog(opts *sign.BundleOptions, cfg *v1alpha1.Config) {
	if cfg.SkipRekor {
		return
	}
	url := cfg.RekorURL
	if url == "" {
		url = defaultRekorURL
	}
	rekorOpts := &sign.RekorOptions{
		BaseURL: url,
		Timeout: defaultRekorTimeout,
		Retries: 1,
	}
	if cfg.RekorVersion != 0 {
		rekorOpts.Version = cfg.RekorVersion
	}
	opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(rekorOpts))
}

// configureFromSigningConfig loads a signing_config.json and uses it to discover
// Fulcio, Rekor, and TSA endpoints, replacing the individual URL config fields.
func configureFromSigningConfig(opts *sign.BundleOptions, cfg *v1alpha1.Config, idToken string) error {
	sc, err := root.NewSigningConfigFromPath(cfg.SigningConfigPath)
	if err != nil {
		return fmt.Errorf("load signing config: %w", err)
	}

	now := time.Now()

	if idToken != "" {
		fulcioSvc, err := root.SelectService(sc.FulcioCertificateAuthorityURLs(), sign.FulcioAPIVersions, now)
		if err != nil {
			return fmt.Errorf("select fulcio service: %w", err)
		}
		opts.CertificateProvider = sign.NewFulcio(&sign.FulcioOptions{
			BaseURL: fulcioSvc.URL,
			Timeout: defaultTimeout,
			Retries: 1,
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
			Timeout: defaultRekorTimeout,
			Retries: 1,
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
			URL:     tsaSvc.URL,
			Timeout: defaultTimeout,
			Retries: 1,
		}))
	}

	return nil
}

// extractIssuer attempts to extract the OIDC issuer from the Fulcio certificate in the bundle.
// It tries the v2 extension (OID 1.3.6.1.4.1.57264.1.8) first, which uses proper ASN.1
// encoding, then falls back to the v1 extension (OID 1.3.6.1.4.1.57264.1.1), which stores
// the issuer as raw UTF-8 bytes without ASN.1 wrapping (a known non-RFC5280 quirk in Fulcio).
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

	// Try v2 issuer extension first (proper ASN.1 UTF8String encoding).
	// OID: 1.3.6.1.4.1.57264.1.8
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.57264.1.8" {
			var issuer string
			if _, err := asn1.Unmarshal(ext.Value, &issuer); err == nil && issuer != "" {
				return issuer
			}
		}
	}

	// Fall back to v1 issuer extension (raw UTF-8 bytes, not ASN.1 wrapped).
	// OID: 1.3.6.1.4.1.57264.1.1
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.57264.1.1" {
			// Try ASN.1 first (some issuers wrap the value properly).
			var issuer string
			if _, err := asn1.Unmarshal(ext.Value, &issuer); err == nil && issuer != "" {
				return issuer
			}
			// Fall back to raw bytes (Fulcio's original non-RFC5280 encoding).
			if len(ext.Value) > 0 {
				return string(ext.Value)
			}
		}
	}

	return ""
}

// ecdsaKeypair adapts an *ecdsa.PrivateKey to sigstore-go's sign.Keypair interface.
type ecdsaKeypair struct {
	privKey *ecdsa.PrivateKey
	hint    []byte
}

func newECDSAKeypair(privKey *ecdsa.PrivateKey) (*ecdsaKeypair, error) {
	hint, err := computeKeyHint(privKey)
	if err != nil {
		return nil, fmt.Errorf("compute key hint: %w", err)
	}
	return &ecdsaKeypair{privKey: privKey, hint: hint}, nil
}

func computeKeyHint(privKey *ecdsa.PrivateKey) ([]byte, error) {
	pubBytes, err := cryptoutils.MarshalPublicKeyToPEM(privKey.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal public key to PEM: %w", err)
	}
	h := sha256.Sum256(pubBytes)
	return []byte(base64.StdEncoding.EncodeToString(h[:])), nil
}

func (k *ecdsaKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return protocommon.HashAlgorithm_SHA2_256
}

func (k *ecdsaKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
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
	h := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, k.privKey, h[:])
	if err != nil {
		return nil, nil, err
	}
	return sig, h[:], nil
}

// signWithConfig is the internal sign implementation called from Handler.Sign.
func signWithConfig(
	ctx context.Context,
	unsigned descruntime.Digest,
	rawCfg runtime.Typed,
	creds map[string]string,
	scheme *runtime.Scheme,
) (descruntime.SignatureInfo, error) {
	var cfg v1alpha1.Config
	if err := scheme.Convert(rawCfg, &cfg); err != nil {
		return descruntime.SignatureInfo{}, fmt.Errorf("convert config: %w", err)
	}

	return doSign(ctx, unsigned, &cfg, creds)
}
