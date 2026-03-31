package handler

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"

	descruntime "ocm.software/open-component-model/bindings/go/descriptor/runtime"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/handler/internal/credentials"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/v1alpha1"
)

func doVerify(
	ctx context.Context,
	signed descruntime.Signature,
	cfg *v1alpha1.Config,
	creds map[string]string,
) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}

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

	pubKey, err := credentials.PublicKeyFromCredentials(creds)
	if err != nil {
		return fmt.Errorf("load public key for verifier: %w", err)
	}

	trustedMaterial, err := resolveTrustedMaterial(ctx, cfg, creds, pubKey)
	if err != nil {
		return fmt.Errorf("resolve trusted material: %w", err)
	}

	verifier, err := buildVerifier(trustedMaterial, cfg, pubKey != nil)
	if err != nil {
		return fmt.Errorf("build verifier: %w", err)
	}

	digestBytes, err := hex.DecodeString(signed.Digest.Value)
	if err != nil {
		return fmt.Errorf("decode digest hex: %w", err)
	}

	policy, err := buildPolicy(bytes.NewReader(digestBytes), pubKey, cfg)
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
// When a public key is provided, it takes precedence as the signing key
// verifier. If a trusted root is also available (via credentials, config path,
// or TUF), it is composed with the key material so that transparency log
// entries can be verified against the trusted root while signatures are
// verified against the provided public key.
//
// Without a public key the function falls back to a trusted root alone
// (keyless / certificate-based verification).
func resolveTrustedMaterial(ctx context.Context, cfg *v1alpha1.Config, creds map[string]string, pubKey crypto.PublicKey) (root.TrustedMaterial, error) {
	trustedRoot, err := resolveTrustedRoot(ctx, cfg, creds)
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

	return nil, fmt.Errorf("no trusted material available: provide a public key, trusted root, or enable network access for public-good TUF")
}

// resolveTrustedRoot loads a trusted root from the first available source:
// credentials JSON, config file path, TUF (when TUFRootURL is set), or the
// public-good Sigstore TUF repository (when no explicit source is configured
// and Rekor is not skipped).
//
// Returns nil, nil only when SkipRekor is set and no explicit source is
// configured. For all other zero-config cases the public-good trusted root
// is fetched automatically.
func resolveTrustedRoot(ctx context.Context, cfg *v1alpha1.Config, creds map[string]string) (root.TrustedMaterial, error) {
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

	// TUF is only used when an explicit TUF mirror URL is configured.
	if cfg.TUFRootURL != "" {
		return trustedMaterialFromTUF(ctx, cfg)
	}

	if cfg.SkipRekor {
		return nil, nil
	}

	slog.InfoContext(ctx, "no trusted root configured, fetching from public-good Sigstore TUF")
	tr, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("fetch public Sigstore trusted root: %w", err)
	}
	return tr, nil
}

// resolveOfflineTrustedRoot loads a trusted root from offline sources only:
// credentials JSON or config file path. Unlike resolveTrustedRoot, it never
// falls back to TUF (which requires network access). Returns nil, nil when
// no offline source is configured.
func resolveOfflineTrustedRoot(cfg *v1alpha1.Config, creds map[string]string) (root.TrustedMaterial, error) {
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

	return nil, nil
}

// trustedMaterialFromPublicKey creates a TrustedMaterial from a public key.
// Supported types: ECDSA (P-256, P-384, P-521) and Ed25519.
// The key is wrapped in a non-expiring verifier that matches any hint.
func trustedMaterialFromPublicKey(pubKey crypto.PublicKey) (root.TrustedMaterial, error) {
	verifier, err := signature.LoadVerifier(pubKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("create verifier: %w", err)
	}

	key := root.NewExpiringKey(verifier, time.Time{}, time.Time{})

	return root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
		return key, nil
	}), nil
}

// trustedMaterialFromTUF fetches a trusted root from a custom TUF mirror.
// cfg.TUFRootURL and cfg.TUFInitialRoot must both be set. The initial root
// serves as the cryptographic trust anchor — the TUF security model requires
// a known-good initial root.json to verify all subsequent metadata.
// Local caching is disabled to avoid conflicts between different TUF repositories.
func trustedMaterialFromTUF(ctx context.Context, cfg *v1alpha1.Config) (root.TrustedMaterial, error) {
	if cfg.TUFInitialRoot == "" {
		return nil, fmt.Errorf("TUFInitialRoot is required when TUFRootURL is set: the TUF security model requires a pinned initial root.json as trust anchor")
	}

	opts := tuf.DefaultOptions()
	opts.RepositoryBaseURL = cfg.TUFRootURL
	opts.Root = []byte(cfg.TUFInitialRoot)
	opts.DisableLocalCache = true

	slog.InfoContext(ctx, "fetching trusted root from custom TUF mirror", "url", cfg.TUFRootURL)

	client, err := tuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("create TUF client: %w", err)
	}
	return root.GetTrustedRoot(client)
}

// buildVerifier creates a sigstore-go Verifier with appropriate options based on config.
// isKeyBased indicates whether the verification uses a public key (true) or certificates (false).
// For certificate-based (keyless) verification, SCT verification is enabled when the
// trusted material includes CT log authorities, following sigstore-go's reference pattern.
func buildVerifier(trustedMaterial root.TrustedMaterial, cfg *v1alpha1.Config, isKeyBased bool) (*verify.Verifier, error) {
	var opts []verify.VerifierOption

	hasTSAFromConfig := cfg.TSAURL != ""
	hasTSAFromMaterial := !hasTSAFromConfig && len(trustedMaterial.TimestampingAuthorities()) > 0

	switch {
	case cfg.SkipRekor:
		opts = append(opts, verify.WithNoObserverTimestamps())
	default:
		opts = append(opts, verify.WithTransparencyLog(1))

		switch {
		case cfg.RekorVersion == 2 && (hasTSAFromConfig || hasTSAFromMaterial):
			// Rekor v2 does not produce signed entry timestamps (SETs).
			// WithObserverTimestamps accepts both RFC3161 TSA timestamps and SETs.
			opts = append(opts, verify.WithObserverTimestamps(1))
		case cfg.RekorVersion == 2:
			return nil, fmt.Errorf("Rekor v2 requires a Timestamp Authority (TSA): configure TSAURL or provide trusted material with TSA entries, because v2 does not produce signed entry timestamps")
		case hasTSAFromMaterial:
			// Auto-discovery: TSA available in trusted material (e.g. from public-good TUF).
			// WithObserverTimestamps accepts both v1 SETs and v2 TSA timestamps.
			opts = append(opts, verify.WithObserverTimestamps(1))
		default:
			opts = append(opts, verify.WithIntegratedTimestamps(1))
		}
	}

	if hasTSAFromConfig {
		opts = append(opts, verify.WithSignedTimestamps(1))
	}

	if !isKeyBased && len(trustedMaterial.CTLogs()) > 0 {
		opts = append(opts, verify.WithSignedCertificateTimestamps(1))
	}

	return verify.NewVerifier(trustedMaterial, opts...)
}

// buildPolicy constructs the verification policy.
//
// Two modes are supported in order of precedence:
//  1. Key-based: when pubKey is non-nil, uses WithKey(). Identity fields in
//     config are ignored because key-based verification doesn't use certificates.
//  2. Certificate identity: when identity fields are configured (ExpectedIssuer,
//     ExpectedSAN, or their regex variants), uses WithCertificateIdentity().
//
// If neither a public key nor identity fields are provided, an error is returned.
// Keyless verification without identity constraints is not supported because it
// would accept any Fulcio-issued certificate regardless of the signer.
func buildPolicy(artifact *bytes.Reader, pubKey crypto.PublicKey, cfg *v1alpha1.Config) (verify.PolicyBuilder, error) {
	artifactOpt := verify.WithArtifact(artifact)

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

	return verify.PolicyBuilder{}, fmt.Errorf("keyless verification requires identity config: set ExpectedIssuer/ExpectedSAN or their regex variants")
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

// validateConfig checks config fields for obviously invalid values.
func validateConfig(cfg *v1alpha1.Config) error {
	if cfg.RekorVersion > 2 {
		return fmt.Errorf("unsupported RekorVersion %d: must be 0 (default), 1, or 2", cfg.RekorVersion)
	}
	return nil
}
