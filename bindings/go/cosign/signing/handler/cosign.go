package handler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// Executor abstracts cosign CLI invocations for testability.
type Executor interface {
	SignBlob(ctx context.Context, dataPath string, opts SignOpts) (bundleJSON []byte, err error)
	VerifyBlob(ctx context.Context, dataPath, bundlePath string, opts VerifyOpts) error
}

// SignOpts contains the options for a cosign sign-blob invocation.
type SignOpts struct {
	BundleOutPath string
	IdentityToken string
	FulcioURL     string
	RekorURL      string
	TSAURL        string
}

// VerifyOpts contains the options for a cosign verify-blob invocation.
type VerifyOpts struct {
	CertificateIdentity         string
	CertificateIdentityRegexp   string
	CertificateOIDCIssuer       string
	CertificateOIDCIssuerRegexp string
	TrustedRoot                 string
}

// DefaultExecutor invokes the cosign binary via os/exec.
type DefaultExecutor struct {
	// BinaryPath is the path to the cosign binary. Defaults to "cosign" (resolved via PATH).
	BinaryPath string
}

// NewDefaultExecutor returns an executor that shells out to cosign.
func NewDefaultExecutor() *DefaultExecutor {
	return &DefaultExecutor{BinaryPath: "cosign"}
}

func (e *DefaultExecutor) SignBlob(ctx context.Context, dataPath string, opts SignOpts) ([]byte, error) {
	args := []string{"sign-blob", dataPath, "--bundle", opts.BundleOutPath, "--yes"}

	if opts.IdentityToken != "" {
		args = append(args, "--identity-token", opts.IdentityToken)
	} else {
		args = append(args, "--fulcio-auth-flow", "normal")
	}
	if opts.FulcioURL != "" {
		args = append(args, "--fulcio-url", opts.FulcioURL)
	}
	if opts.RekorURL != "" {
		args = append(args, "--rekor-url", opts.RekorURL)
	}
	if opts.TSAURL != "" {
		args = append(args, "--timestamp-server-url", opts.TSAURL)
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, e.BinaryPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cosign sign-blob failed: %w\nstderr: %s", err, stderr.String())
	}

	bundleJSON, err := os.ReadFile(opts.BundleOutPath)
	if err != nil {
		return nil, fmt.Errorf("read bundle output: %w", err)
	}

	return bundleJSON, nil
}

func (e *DefaultExecutor) VerifyBlob(ctx context.Context, dataPath, bundlePath string, opts VerifyOpts) error {
	args := []string{"verify-blob", dataPath, "--bundle", bundlePath}

	if opts.CertificateIdentity != "" {
		args = append(args, "--certificate-identity", opts.CertificateIdentity)
	}
	if opts.CertificateIdentityRegexp != "" {
		args = append(args, "--certificate-identity-regexp", opts.CertificateIdentityRegexp)
	}
	if opts.CertificateOIDCIssuer != "" {
		args = append(args, "--certificate-oidc-issuer", opts.CertificateOIDCIssuer)
	}
	if opts.CertificateOIDCIssuerRegexp != "" {
		args = append(args, "--certificate-oidc-issuer-regexp", opts.CertificateOIDCIssuerRegexp)
	}
	if opts.TrustedRoot != "" {
		args = append(args, "--trusted-root", opts.TrustedRoot)
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, e.BinaryPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cosign verify-blob failed: %w\nstderr: %s", err, stderr.String())
	}

	return nil
}
