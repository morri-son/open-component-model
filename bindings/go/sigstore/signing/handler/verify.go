package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	descruntime "ocm.software/open-component-model/bindings/go/descriptor/runtime"
	"ocm.software/open-component-model/bindings/go/runtime"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/handler/internal/credentials"
	"ocm.software/open-component-model/bindings/go/sigstore/signing/v1alpha1"
)

func doVerify(
	ctx context.Context,
	signed descruntime.Signature,
	cfg *v1alpha1.VerifyConfig,
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

	trustedMaterial, err := resolveTrustedMaterial(ctx, cfg, creds)
	if err != nil {
		return fmt.Errorf("resolve trusted material: %w", err)
	}

	verifier, err := buildVerifier(trustedMaterial)
	if err != nil {
		return fmt.Errorf("build verifier: %w", err)
	}

	digestBytes, err := hex.DecodeString(signed.Digest.Value)
	if err != nil {
		return fmt.Errorf("decode digest hex: %w", err)
	}

	policy, err := buildPolicy(bytes.NewReader(digestBytes), cfg)
	if err != nil {
		return fmt.Errorf("build verification policy: %w", err)
	}

	if _, err := verifier.Verify(sigBundle, policy); err != nil {
		return fmt.Errorf("sigstore verification failed: %w", err)
	}

	return nil
}

// resolveTrustedMaterial builds the trusted material for keyless verification.
// A trusted root is required for Fulcio CA chain verification and is resolved
// from the first available source: credentials JSON, config file path, TUF
// mirror, or the public-good Sigstore TUF repository as fallback.
func resolveTrustedMaterial(ctx context.Context, cfg *v1alpha1.VerifyConfig, creds map[string]string) (root.TrustedMaterial, error) {
	trustedRoot, err := resolveTrustedRoot(ctx, cfg, creds)
	if err != nil {
		return nil, err
	}
	if trustedRoot != nil {
		return trustedRoot, nil
	}

	return nil, fmt.Errorf("no trusted material available: provide a trusted root or enable network access for public-good TUF")
}

// resolveTrustedRootExplicit loads a trusted root from explicit sources only:
// credentials JSON, config file path, or a configured TUF mirror URL.
// It does NOT fall back to public-good TUF auto-discovery.
// Returns nil, nil when no explicit source is configured.
func resolveTrustedRootExplicit(ctx context.Context, cfg *v1alpha1.VerifyConfig, creds map[string]string) (root.TrustedMaterial, error) {
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
		return trustedMaterialFromTUF(ctx, cfg)
	}

	return nil, nil
}

// resolveTrustedRoot loads a trusted root from the first available source:
// credentials JSON, config file path, TUF (when TUFRootURL is set), or the
// public-good Sigstore TUF repository as fallback.
func resolveTrustedRoot(ctx context.Context, cfg *v1alpha1.VerifyConfig, creds map[string]string) (root.TrustedMaterial, error) {
	tm, err := resolveTrustedRootExplicit(ctx, cfg, creds)
	if err != nil {
		return nil, err
	}
	if tm != nil {
		return tm, nil
	}

	slog.InfoContext(ctx, "no trusted root configured, fetching from public-good Sigstore TUF")
	tr, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("fetch public Sigstore trusted root: %w", err)
	}
	return tr, nil
}

// resolveOfflineTrustedRoot loads a trusted root from offline sources only:
// credentials JSON. Unlike resolveTrustedRoot, it never falls back to TUF
// (which requires network access). Returns nil, nil when no offline source
// is configured.
func resolveOfflineTrustedRoot(creds map[string]string) (root.TrustedMaterial, error) {
	trustedRootJSON, err := credentials.TrustedRootFromCredentials(creds)
	if err != nil {
		return nil, fmt.Errorf("load trusted root from credentials: %w", err)
	}
	if len(trustedRootJSON) > 0 {
		return root.NewTrustedRootFromJSON(trustedRootJSON)
	}

	return nil, nil
}

// trustedMaterialFromTUF fetches a trusted root from a custom TUF mirror.
// cfg.TUFRootURL and cfg.TUFInitialRoot must both be set. The initial root
// serves as the cryptographic trust anchor — the TUF security model requires
// a known-good initial root.json to verify all subsequent metadata.
// Local caching is disabled to avoid conflicts between different TUF repositories.
func trustedMaterialFromTUF(ctx context.Context, cfg *v1alpha1.VerifyConfig) (root.TrustedMaterial, error) {
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

// buildVerifier creates a sigstore-go Verifier with appropriate options based on the
// trusted material available. Transparency log and timestamp requirements are auto-detected
// from the trusted material. SCT verification is enabled when the trusted material
// includes CT log authorities, following sigstore-go's reference pattern.
func buildVerifier(trustedMaterial root.TrustedMaterial) (*verify.Verifier, error) {
	var opts []verify.VerifierOption

	hasRekorLogs := len(trustedMaterial.RekorLogs()) > 0
	if hasRekorLogs {
		opts = append(opts, verify.WithTransparencyLog(1))

		hasTSA := len(trustedMaterial.TimestampingAuthorities()) > 0
		if hasTSA {
			opts = append(opts, verify.WithObserverTimestamps(1))
		} else {
			opts = append(opts, verify.WithIntegratedTimestamps(1))
		}
	} else {
		opts = append(opts, verify.WithNoObserverTimestamps())
	}

	if len(trustedMaterial.CTLogs()) > 0 {
		opts = append(opts, verify.WithSignedCertificateTimestamps(1))
	}

	return verify.NewVerifier(trustedMaterial, opts...)
}

// buildPolicy constructs the verification policy using certificate identity.
// Keyless verification requires identity constraints (ExpectedIssuer/ExpectedSAN
// or their regex variants) to ensure the Fulcio certificate was issued to the
// expected signer.
func buildPolicy(artifact *bytes.Reader, cfg *v1alpha1.VerifyConfig) (verify.PolicyBuilder, error) {
	artifactOpt := verify.WithArtifact(artifact)

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

func hasIdentityConfig(cfg *v1alpha1.VerifyConfig) bool {
	return cfg.ExpectedIssuer != "" || cfg.ExpectedIssuerRegex != "" ||
		cfg.ExpectedSAN != "" || cfg.ExpectedSANRegex != ""
}

func verifyWithConfig(
	ctx context.Context,
	signed descruntime.Signature,
	rawCfg runtime.Typed,
	creds map[string]string,
	scheme *runtime.Scheme,
) error {
	if got := rawCfg.GetType(); got != (runtime.Type{}) && got.GetName() != v1alpha1.VerifyConfigType {
		return fmt.Errorf("expected config type %s but got %s", v1alpha1.VerifyConfigType, got)
	}

	var cfg v1alpha1.VerifyConfig
	if err := scheme.Convert(rawCfg, &cfg); err != nil {
		return fmt.Errorf("convert config: %w", err)
	}

	return doVerify(ctx, signed, &cfg, creds)
}
