package handler

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	descruntime "ocm.software/open-component-model/bindings/go/descriptor/runtime"

	"ocm.software/open-component-model/bindings/go/cosign/signing/v1alpha1"
)

func doVerify(
	ctx context.Context,
	signed descruntime.Signature,
	cfg *v1alpha1.VerifyConfig,
	creds map[string]string,
	executor Executor,
) error {
	if !hasIdentityConfig(cfg) {
		return fmt.Errorf("keyless verification requires identity config: set ExpectedIssuer/ExpectedSAN or their regex variants")
	}

	bundleJSON, err := base64.StdEncoding.DecodeString(signed.Signature.Value)
	if err != nil {
		return fmt.Errorf("decode bundle base64: %w", err)
	}

	bundleFile, err := os.CreateTemp("", "cosign-verify-bundle-*.json")
	if err != nil {
		return fmt.Errorf("create temp bundle file: %w", err)
	}
	defer os.Remove(bundleFile.Name())
	if _, err := bundleFile.Write(bundleJSON); err != nil {
		bundleFile.Close()
		return fmt.Errorf("write bundle to temp file: %w", err)
	}
	bundleFile.Close()

	digestBytes, err := hex.DecodeString(signed.Digest.Value)
	if err != nil {
		return fmt.Errorf("decode digest hex: %w", err)
	}

	dataFile, err := os.CreateTemp("", "cosign-verify-data-*")
	if err != nil {
		return fmt.Errorf("create temp data file: %w", err)
	}
	defer os.Remove(dataFile.Name())
	if _, err := dataFile.Write(digestBytes); err != nil {
		dataFile.Close()
		return fmt.Errorf("write digest to temp file: %w", err)
	}
	dataFile.Close()

	trustedRootPath, cleanup, err := resolveTrustedRootPath(cfg, creds)
	if err != nil {
		return fmt.Errorf("resolve trusted root: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	opts := VerifyOpts{
		CertificateIdentity:         cfg.ExpectedSAN,
		CertificateIdentityRegexp:   cfg.ExpectedSANRegex,
		CertificateOIDCIssuer:       cfg.ExpectedIssuer,
		CertificateOIDCIssuerRegexp: cfg.ExpectedIssuerRegex,
		TrustedRoot:                 trustedRootPath,
	}

	if err := executor.VerifyBlob(ctx, dataFile.Name(), bundleFile.Name(), opts); err != nil {
		return fmt.Errorf("cosign verification failed: %w", err)
	}

	return nil
}

// resolveTrustedRootPath returns a file path to the trusted root JSON.
// If the trusted root is provided inline via credentials, it writes it to a temp file
// and returns a cleanup function. Returns empty string if no trusted root is configured
// (cosign will fall back to public-good TUF).
func resolveTrustedRootPath(cfg *v1alpha1.VerifyConfig, creds map[string]string) (string, func(), error) {
	if jsonVal := creds[CredentialKeyTrustedRootJSON]; jsonVal != "" {
		tmpFile, err := os.CreateTemp("", "cosign-trusted-root-*.json")
		if err != nil {
			return "", nil, fmt.Errorf("create temp trusted root file: %w", err)
		}
		if _, err := tmpFile.WriteString(jsonVal); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return "", nil, fmt.Errorf("write trusted root to temp file: %w", err)
		}
		tmpFile.Close()
		return tmpFile.Name(), func() { os.Remove(tmpFile.Name()) }, nil
	}

	if filePath := creds[CredentialKeyTrustedRootJSONFile]; filePath != "" {
		return filePath, nil, nil
	}

	if cfg.TrustedRootPath != "" {
		return cfg.TrustedRootPath, nil, nil
	}

	return "", nil, nil
}

func hasIdentityConfig(cfg *v1alpha1.VerifyConfig) bool {
	return cfg.ExpectedIssuer != "" || cfg.ExpectedIssuerRegex != "" ||
		cfg.ExpectedSAN != "" || cfg.ExpectedSANRegex != ""
}
