package handler

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"

	descruntime "ocm.software/open-component-model/bindings/go/descriptor/runtime"
	"ocm.software/open-component-model/bindings/go/runtime"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/handler/internal/credentials"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/v1alpha1"
)

func doVerify(
	ctx context.Context,
	signed descruntime.Signature,
	cfg *v1alpha1.Config,
	creds map[string]string,
) error {
	bundleJSON, err := base64.StdEncoding.DecodeString(signed.Signature.Value)
	if err != nil {
		return fmt.Errorf("decode bundle base64: %w", err)
	}

	var pbundle protobundle.Bundle
	if err := protojson.Unmarshal(bundleJSON, &pbundle); err != nil {
		return fmt.Errorf("unmarshal sigstore bundle: %w", err)
	}

	sigBundle, err := bundle.NewBundle(&pbundle)
	if err != nil {
		return fmt.Errorf("validate sigstore bundle: %w", err)
	}

	trustedMaterial, err := resolveTrustedMaterial(cfg, creds)
	if err != nil {
		return fmt.Errorf("resolve trusted material: %w", err)
	}

	verifier, err := buildVerifier(trustedMaterial, cfg)
	if err != nil {
		return fmt.Errorf("build verifier: %w", err)
	}

	digestBytes, err := hex.DecodeString(signed.Digest.Value)
	if err != nil {
		return fmt.Errorf("decode digest hex: %w", err)
	}

	policy, err := buildPolicy(bytes.NewReader(digestBytes), creds, cfg)
	if err != nil {
		return fmt.Errorf("build verification policy: %w", err)
	}

	if _, err := verifier.Verify(sigBundle, policy); err != nil {
		return fmt.Errorf("sigstore verification failed: %w", err)
	}

	return nil
}

// resolveTrustedMaterial builds the trusted material for verification.
//
// When a public key is provided via credentials, it takes precedence as the
// signing key verifier. If a trusted root is also available (via credentials,
// config path, or TUF), it is composed with the key material so that
// transparency log entries can be verified against the trusted root while
// signatures are verified against the provided public key.
//
// Without a public key the function falls back to a trusted root alone
// (keyless / certificate-based verification).
func resolveTrustedMaterial(cfg *v1alpha1.Config, creds map[string]string) (root.TrustedMaterial, error) {
	pubKey, err := credentials.PublicKeyFromCredentials(creds)
	if err != nil {
		return nil, fmt.Errorf("load public key from credentials: %w", err)
	}

	trustedRoot, err := resolveTrustedRoot(cfg, creds)
	if err != nil {
		return nil, err
	}

	if pubKey != nil {
		keyMaterial, err := trustedMaterialFromPublicKey(pubKey)
		if err != nil {
			return nil, err
		}
		if trustedRoot != nil {
			return &composedTrustedMaterial{
				TrustedMaterial:    trustedRoot,
				keyTrustedMaterial: keyMaterial,
			}, nil
		}
		return keyMaterial, nil
	}

	if trustedRoot != nil {
		return trustedRoot, nil
	}

	return nil, fmt.Errorf("no trusted material available: provide a public key, trusted root, or TUF root URL")
}

// resolveTrustedRoot loads a trusted root from the first available source:
// credentials JSON, config file path, or TUF.
// Returns nil, nil when no source is configured.
func resolveTrustedRoot(cfg *v1alpha1.Config, creds map[string]string) (root.TrustedMaterial, error) {
	trustedRootJSON, err := credentials.TrustedRootFromCredentials(creds)
	if err != nil {
		return nil, fmt.Errorf("load trusted root from credentials: %w", err)
	}
	if len(trustedRootJSON) > 0 {
		return root.NewTrustedRootFromJSON(trustedRootJSON)
	}

	if cfg.TrustedRootPath != "" {
		return root.NewTrustedRootFromPath(cfg.TrustedRootPath)
	}

	if cfg.TUFRootURL != "" {
		return trustedMaterialFromTUF(cfg)
	}

	return nil, nil
}

// trustedMaterialFromPublicKey creates a TrustedMaterial from an ECDSA public key.
// It wraps the key in a non-expiring verifier that matches any hint.
func trustedMaterialFromPublicKey(pubKey *ecdsa.PublicKey) (root.TrustedMaterial, error) {
	verifier, err := signature.LoadECDSAVerifier(pubKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("create ECDSA verifier: %w", err)
	}

	key := root.NewExpiringKey(verifier, time.Time{}, time.Time{})

	return root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
		return key, nil
	}), nil
}

// trustedMaterialFromTUF fetches a trusted root via TUF.
// If cfg.TUFRootURL is set, it uses that as the TUF mirror and fetches its
// root.json as the trust anchor. Otherwise it defaults to the Sigstore
// public-good instance with its embedded root.
func trustedMaterialFromTUF(cfg *v1alpha1.Config) (root.TrustedMaterial, error) {
	opts := tuf.DefaultOptions()
	if cfg.TUFRootURL != "" {
		opts.RepositoryBaseURL = cfg.TUFRootURL

		// Custom TUF mirrors use their own root of trust. Fetch the
		// remote root.json and use it as the trust anchor instead of the
		// embedded Sigstore public-good root.
		remoteRoot, err := fetchTUFRoot(cfg.TUFRootURL)
		if err != nil {
			return nil, fmt.Errorf("fetch TUF root from %s: %w", cfg.TUFRootURL, err)
		}
		opts.Root = remoteRoot
		// Disable local cache to avoid conflicts between different TUF
		// repositories sharing the same cache path.
		opts.DisableLocalCache = true
	}
	client, err := tuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("create TUF client: %w", err)
	}
	return root.GetTrustedRoot(client)
}

// fetchTUFRoot fetches root.json from a TUF mirror URL.
func fetchTUFRoot(baseURL string) ([]byte, error) {
	resp, err := http.Get(baseURL + "/root.json") //nolint:gosec,noctx // TUF root fetch is a one-off bootstrap operation.
	if err != nil {
		return nil, fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// buildVerifier creates a sigstore-go Verifier with appropriate options based on config.
func buildVerifier(trustedMaterial root.TrustedMaterial, cfg *v1alpha1.Config) (*verify.Verifier, error) {
	var opts []verify.VerifierOption

	hasTSA := cfg.ForceTSA || cfg.TSAURL != ""

	switch {
	case cfg.SkipRekor:
		opts = append(opts, verify.WithNoObserverTimestamps())
	default:
		opts = append(opts, verify.WithTransparencyLog(1))
		// Rekor v2 does not produce signed entry timestamps (SETs), so
		// integrated timestamps are only available from Rekor v1. For v2
		// without a TSA, we skip timestamp requirements — the checkpoint
		// and inclusion proof still provide log integrity guarantees.
		if cfg.RekorVersion == 2 {
			if hasTSA {
				opts = append(opts, verify.WithObserverTimestamps(1))
			} else {
				opts = append(opts, verify.WithNoObserverTimestamps())
			}
		} else {
			opts = append(opts, verify.WithIntegratedTimestamps(1))
		}
	}

	if hasTSA {
		opts = append(opts, verify.WithSignedTimestamps(1))
	}

	return verify.NewVerifier(trustedMaterial, opts...)
}

// buildPolicy constructs the verification policy.
//
// Three modes are supported in order of precedence:
//  1. Key-based: when a public key is present in creds, uses WithKey(). Identity
//     fields in config are ignored because key-based verification doesn't use certificates.
//  2. Certificate identity: when identity fields are configured (ExpectedIssuer,
//     ExpectedSAN, or their regex variants), uses WithCertificateIdentity().
//  3. Unsafe fallback: when neither a public key nor identity fields are provided,
//     falls back to WithoutIdentitiesUnsafe(). This skips certificate identity
//     checks entirely — the bundle's signature is verified against the trusted root
//     but the signer's identity is not constrained. Use with caution.
func buildPolicy(artifact *bytes.Reader, creds map[string]string, cfg *v1alpha1.Config) (verify.PolicyBuilder, error) {
	artifactOpt := verify.WithArtifact(artifact)

	pubKey, err := credentials.PublicKeyFromCredentials(creds)
	if err != nil {
		return verify.PolicyBuilder{}, fmt.Errorf("load public key for policy: %w", err)
	}

	if pubKey != nil {
		return verify.NewPolicy(artifactOpt, verify.WithKey()), nil
	}

	if hasIdentityConfig(cfg) {
		certID, err := verify.NewShortCertificateIdentity(
			cfg.ExpectedIssuer,
			cfg.ExpectedIssuerRegex,
			cfg.ExpectedSAN,
			cfg.ExpectedSANRegex,
		)
		if err != nil {
			return verify.PolicyBuilder{}, fmt.Errorf("build certificate identity: %w", err)
		}
		return verify.NewPolicy(artifactOpt, verify.WithCertificateIdentity(certID)), nil
	}

	return verify.NewPolicy(artifactOpt, verify.WithoutIdentitiesUnsafe()), nil
}

// composedTrustedMaterial combines a trusted root (providing Rekor/CT/TSA
// verification data) with key-based trusted material (providing the signing
// key verifier). This is needed when verifying key-based signatures that also
// have transparency log entries — the verifier needs both the public key and
// the trusted root's log verification data.
type composedTrustedMaterial struct {
	root.TrustedMaterial
	keyTrustedMaterial root.TrustedMaterial
}

func (c *composedTrustedMaterial) PublicKeyVerifier(hint string) (root.TimeConstrainedVerifier, error) {
	return c.keyTrustedMaterial.PublicKeyVerifier(hint)
}

func hasIdentityConfig(cfg *v1alpha1.Config) bool {
	return cfg.ExpectedIssuer != "" || cfg.ExpectedIssuerRegex != "" ||
		cfg.ExpectedSAN != "" || cfg.ExpectedSANRegex != ""
}

// verifyWithConfig is the internal verify implementation called from Handler.Verify.
func verifyWithConfig(
	ctx context.Context,
	signed descruntime.Signature,
	rawCfg runtime.Typed,
	creds map[string]string,
	scheme *runtime.Scheme,
) error {
	var cfg v1alpha1.Config
	if err := scheme.Convert(rawCfg, &cfg); err != nil {
		return fmt.Errorf("convert config: %w", err)
	}

	return doVerify(ctx, signed, &cfg, creds)
}
