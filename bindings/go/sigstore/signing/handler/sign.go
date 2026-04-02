package handler

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
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
		return descruntime.SignatureInfo{}, fmt.Errorf("keyless signing requires an OIDC identity token: provide one via credentials or configure explicit endpoints")
	}

	// When a trusted root is available from an offline source, set it on
	// BundleOptions so sign.Bundle can verify the created bundle before
	// returning it (defense-in-depth). TUF is intentionally excluded to
	// avoid a network round-trip at sign time.
	if tr, err := resolveOfflineTrustedRoot(creds); err != nil {
		slog.WarnContext(ctx, "failed to resolve offline trusted root for sign-time verification", "error", err)
	} else if tr != nil {
		opts.TrustedRoot = tr
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

// resolveKeypair returns an ephemeral signing keypair and the OIDC identity
// token from credentials (if available).
func resolveKeypair(creds map[string]string) (sign.Keypair, string, error) {
	idToken := credentials.OIDCTokenFromCredentials(creds)

	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, "", fmt.Errorf("create ephemeral keypair: %w", err)
	}
	return keypair, idToken, nil
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
	if got := rawCfg.GetType(); got != (runtime.Type{}) && got.GetName() != v1alpha1.SignConfigType {
		return descruntime.SignatureInfo{}, fmt.Errorf("expected config type %s but got %s", v1alpha1.SignConfigType, got)
	}

	var cfg v1alpha1.SignConfig
	if err := scheme.Convert(rawCfg, &cfg); err != nil {
		return descruntime.SignatureInfo{}, fmt.Errorf("convert config: %w", err)
	}

	return doSign(ctx, unsigned, &cfg, creds)
}
